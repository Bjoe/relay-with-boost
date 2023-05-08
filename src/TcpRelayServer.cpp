#include "TcpRelayServer.hpp"

#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>
#include <poll.h>
#include <errno.h>
#include <thread>
#include <sstream>
#include <linux/bpf.h>
#include <fcntl.h> // to add splice()
#include <linux/aio_abi.h> // to add iocb

extern "C" {
#include "sockmap/tbpf.h"
#include "iosubmit.h" // this implementation can't crosscompile, use libaio -> https://pagure.io/libaio
};

namespace relay {

class TcpSession : public std::enable_shared_from_this<TcpSession>
{
public:
  TcpSession(
    boost::asio::io_context& io_context,
    std::shared_ptr<boost::asio::ip::tcp::socket> peerSocket,
    boost::asio::ip::tcp::endpoint destinationEndpoint,
    const std::size_t buffer_size,
    int sock_map,
    Options options) :
        peerSocket_{std::move(peerSocket)},
        clientSocket_{io_context},
        destination_endpoint_{std::move(destinationEndpoint)},
        serverBuffer_(buffer_size),
        clientBuffer_(buffer_size),
        buffer_size_(buffer_size),
        sock_map_(sock_map),
        options_(options)
    {
    }

    ~TcpSession() {
        for(auto& t : runnerThreads_) {
            t.join();
        }
    }

    // TODO add missing special member function (rulse of 5)

    void start()
    {
        auto self{shared_from_this()};

        clientSocket_.async_connect(
            destination_endpoint_,
            [this, self](const boost::system::error_code& error_code)
            {
                if (!error_code)
                {
              switch(options_) {
              case Options::TCP_RELAY:
              {
                BOOST_LOG_TRIVIAL(info) << "Start TCP relay: Connect from " << clientSocket_.local_endpoint() << " to " << destination_endpoint_;

                readclient_handler();
                read_handler();
              }
              break;
              case Options::SOCKMAP_RELAY:
              {
                BOOST_LOG_TRIVIAL(info) << "Start sockmap() relay: Connect from " << clientSocket_.local_endpoint() << " to " << destination_endpoint_;
                sockmap_relay();
              }
              break;
              case Options::IOSUBMIT_RELAY:
              {
                BOOST_LOG_TRIVIAL(info) << "Start io_submit() relay: Connect from " << clientSocket_.local_endpoint() << " to " << destination_endpoint_;
                iosubmit_relay();
              }
              break;
              case Options::SPLICE_RELAY:
              {
                BOOST_LOG_TRIVIAL(info) << "Start splice() relay: Connect from " << clientSocket_.local_endpoint() << " to " << destination_endpoint_;
                splice_relay();
              }
              break;
              }
                }
            });

    }

    void sockmap_relay()
    {
        int fd = peerSocket_->native_handle();
        int fd_out = clientSocket_.native_handle();
        {
          /* There is a bug in sockmap which prevents it from
           * working right when snd buffer is full. Set it to
           * gigantic value. */
          int val = 32 * 1024 * 1024;
          setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        }

        /* [*] Perform ebpf socket magic */
        /* Add socket to SOCKMAP. Otherwise the ebpf won't work. */
        int idx = 0;
        int val = fd;
        int r = tbpf_map_update_elem(sock_map_, &idx, &val, BPF_ANY);
        if (r != 0) {
          if (errno == EOPNOTSUPP) {
            throw std::logic_error("pushing closed socket to sockmap?");
          }
          throw std::logic_error("bpf(MAP_UPDATE_ELEM)");
        }

        int idx_out = 1;
        int val_out = fd_out;
        r = tbpf_map_update_elem(sock_map_, &idx_out, &val_out, BPF_ANY);
        if (r != 0) {
          if (errno == EOPNOTSUPP) {
            throw std::logic_error("pushing closed socket to sockmap?");
          }
          throw std::logic_error("bpf(MAP_UPDATE_ELEM)");
        }

        /* [*] Wait for the socket to close. Let sockmap do the magic. */
        struct pollfd fds[1]{};
        fds[0].fd = fd;
        fds[0].events = POLLRDHUP;

        poll(fds, 1, -1);

        /* Was there a socket error? */
        {
          int err;
          socklen_t err_len = sizeof(err);
          r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
          if (r < 0) {
            throw std::logic_error("getsockopt()");
          }
          errno = err;
          if (errno) {
            throw std::logic_error("sockmap fd");
          }
        }

        /* Cleanup the entry from sockmap. */
        idx = 0;
        r = tbpf_map_delete_elem(sock_map_, &idx);
        if (r != 0) {
          if (errno == EINVAL) {
            BOOST_LOG_TRIVIAL(error) << "[-] Removing closed sock from sockmap\n";
          } else {
            throw std::logic_error("bpf(MAP_DELETE_ELEM, sock_map)");
          }
        }
        close(fd);
    }

    void splice_relay()
    {
        int cd = peerSocket_->native_handle();
        int fd_out = clientSocket_.native_handle();

        int flags = fcntl(cd, F_GETFL, 0);
        if (flags == -1) {
          throw std::logic_error("Get fcntl() fails");
        }
        flags = flags & ~O_NONBLOCK;
        int r = fcntl(cd, F_SETFL, flags);
        if ( r < 0) {
          throw std::logic_error("Set fcntl() fails");
        }


        int outFlags = fcntl(fd_out, F_GETFL, 0);
        if (outFlags == -1) {
          throw std::logic_error("Get fcntl() fails");
        }
        fd_out = fd_out & ~O_NONBLOCK;
        r = fcntl(fd_out, F_SETFL, fd_out);
        if ( r < 0) {
          throw std::logic_error("Set fcntl() fails");
        }


        runnerThreads_.emplace_back(
                                 [cd, fd_out]() {
                                     int pfd[2];
                                     int r = pipe(pfd);
                                     if (r < 0) {
                                         throw std::logic_error("Create pipe() fails");
                                     }

          /* There is no "good" splice buffer size. Anecdotical evidence
         * says that it should be no larger than 512KiB since this is
         * the max we can expect realistically to fit into cpu
         * cache. */
#define SPLICE_MAX (512*1024)

                                     r = fcntl(pfd[0], F_SETPIPE_SZ, SPLICE_MAX);
                                     if (r < 0) {
                                         throw std::logic_error("Create fcntl() fails");
                                     }
                                     while (1) {
                                         /* This is fairly unfair. We are doing 512KiB buffer
               * in one go, as opposed to naive approaches. Cheating. */
                                         ssize_t n = splice(cd, nullptr, pfd[1], nullptr, static_cast<std::size_t>(SPLICE_MAX),
                                                            SPLICE_F_MOVE);
                                         if (n < 0) {
                                             if (errno == ECONNRESET) {
                                                 BOOST_LOG_TRIVIAL(error) << "[!] ECONNRESET\n";
                                                 break;
                                             }
                                             if (errno == EAGAIN) {
                                                 BOOST_LOG_TRIVIAL(error) << "[-] EAGAIN\n";
                                                 break;
                                             }
                                             throw std::logic_error("Create pipe() fails");
                                         }
                                         if (n == 0) {
                                             /* On TCP socket zero means EOF */
                                             BOOST_LOG_TRIVIAL(error) << "[-] edge side EOF\n";
                                             break;
                                         }

                                         ssize_t m = splice(pfd[0], nullptr, fd_out, nullptr, static_cast<std::size_t>(n), SPLICE_F_MOVE);
                                         if (m < 0) {
                                             if (errno == ECONNRESET) {
                                                 BOOST_LOG_TRIVIAL(error) << "[!] ECONNRESET on origin\n";
                                                 break;
                                             }
                                             if (errno == EPIPE) {
                                                 BOOST_LOG_TRIVIAL(error) << "[!] EPIPE on origin\n";
                                                 break;
                                             }
                                             throw std::logic_error("send() fails");
                                         }
                                         if (m == 0) {
                                             int err;
                                             socklen_t err_len = sizeof(err);
                                             int u = getsockopt(cd, SOL_SOCKET, SO_ERROR, &err,
                                                                &err_len);
                                             if (u < 0) {
                                                 throw std::logic_error("getsockopt()");
                                             }
                                             errno = err;
                                             throw std::logic_error("send()");
                                         }
                                         if (m != n) {
                                             throw std::logic_error("expecting splice to block");
                                         }
                                     }
            });


        runnerThreads_.emplace_back(
                                 [cd, fd_out]() {
                                     int pfd[2];
                                     int r = pipe(pfd);
                                     if (r < 0) {
                                         throw std::logic_error("Create pipe() fails");
                                     }

          /* There is no "good" splice buffer size. Anecdotical evidence
         * says that it should be no larger than 512KiB since this is
         * the max we can expect realistically to fit into cpu
         * cache. */
#define SPLICE_MAX (512*1024)

                                     r = fcntl(pfd[0], F_SETPIPE_SZ, SPLICE_MAX);
                                     if (r < 0) {
                                         throw std::logic_error("Create fcntl() fails");
                                     }
                                     while (1) {
                                         /* This is fairly unfair. We are doing 512KiB buffer
                * in one go, as opposed to naive approaches. Cheating. */
                                         ssize_t n = splice(fd_out, nullptr, pfd[1], nullptr, static_cast<std::size_t>(SPLICE_MAX),
                                                            SPLICE_F_MOVE);
                                         if (n < 0) {
                                             if (errno == ECONNRESET) {
                                                 BOOST_LOG_TRIVIAL(error) << "[!] ECONNRESET\n";
                                                 break;
                                             }
                                             if (errno == EAGAIN) {
                                                 BOOST_LOG_TRIVIAL(error) << "[-] EAGAIN\n";
                                                 break;
                                             }
                                             throw std::logic_error("Create pipe() fails");
                                         }
                                         if (n == 0) {
                                             /* On TCP socket zero means EOF */
                                             BOOST_LOG_TRIVIAL(error) << "[-] edge side EOF\n";
                                             break;
                                         }

                                         ssize_t m = splice(pfd[0], nullptr, cd, nullptr, static_cast<std::size_t>(n), SPLICE_F_MOVE);
                                         if (m < 0) {
                                             if (errno == ECONNRESET) {
                                                 BOOST_LOG_TRIVIAL(error) << "[!] ECONNRESET on origin\n";
                                                 break;
                                             }
                                             if (errno == EPIPE) {
                                                 BOOST_LOG_TRIVIAL(error) << "[!] EPIPE on origin\n";
                                                 break;
                                             }
                                             throw std::logic_error("send() fails");
                                         }
                                         if (m == 0) {
                                             int err;
                                             socklen_t err_len = sizeof(err);
                                             int u = getsockopt(cd, SOL_SOCKET, SO_ERROR, &err,
                                                                &err_len);
                                             if (u < 0) {
                                                 throw std::logic_error("getsockopt()");
                                             }
                                             errno = err;
                                             throw std::logic_error("send()");
                                         }
                                         if (m != n) {
                                             throw std::logic_error("expecting splice to block");
                                         }
                                     }
            });
    }

    void iosubmit_relay()
    {
        int cd = peerSocket_->native_handle();
        int fd_out = clientSocket_.native_handle();

        int flags = fcntl(cd, F_GETFL, 0);
        if (flags == -1) {
          throw std::logic_error("Get fcntl() fails");
        }
        flags = flags & ~O_NONBLOCK;
        int r = fcntl(cd, F_SETFL, flags);
        if ( r < 0) {
          throw std::logic_error("Set fcntl() fails");
        }

        int outFlags = fcntl(fd_out, F_GETFL, 0);
        if (outFlags == -1) {
          throw std::logic_error("Get fcntl() fails");
        }
        outFlags = outFlags & ~O_NONBLOCK;
        r = fcntl(fd_out, F_SETFL, outFlags);
        if ( r < 0) {
          throw std::logic_error("Set fcntl() fails");
        }

        aio_context_t ctx = {0};
        r = io_setup(8, &ctx);
        if (r < 0) {
          throw std::logic_error("io_setup()");
        }

#define BUFFER_SIZE (128 * 1024)
        char buf[BUFFER_SIZE];

        struct iocb cb[2];

        cb[0].aio_fildes = fd_out;
        cb[0].aio_lio_opcode = IOCB_CMD_PWRITE;
        cb[0].aio_buf = (uint64_t)buf;
        cb[0].aio_nbytes = 0;

        cb[1].aio_fildes = cd;
        cb[1].aio_lio_opcode = IOCB_CMD_PREAD;
        cb[1].aio_buf = (uint64_t)buf;
        cb[1].aio_nbytes = BUFFER_SIZE;

        struct iocb *list_of_iocb[2] = {&cb[0], &cb[1]};

        // TODO Implement io_submit from fd_out -> cd
        while (1) {
          // io_submit on blocking network sockets will
          // block. It will loop over sockets one by one,
          // blocking on each operation. We abuse this to do
          // write+read in one syscall. In first iteration the
          // write is empty, we do write of size 0.
          r = io_submit(ctx, 2, list_of_iocb);
          if (r != 2) {
            std::ostringstream o{};
            o << "io_submit() r -> " << r << '\n';
            throw std::logic_error(o.str());
          }

          /* We must pick up the result, since we need to get
           * the number of bytes read. */
          struct io_event events[2] = {{0}};
          r = io_getevents(ctx, 1, 2, events, NULL);
          if (r < 0) {
            std::ostringstream o{};
            o << "io_getevents() r -> " << r << '\n';
            throw std::logic_error(o.str());
          }
          if (events[0].res < 0) {
            errno = -events[0].res;
            BOOST_LOG_TRIVIAL(error) << "io_submit(IOCB_CMD_PWRITE): " << strerror(errno);
            break;
          }
          if (events[1].res < 0) {
            errno = -events[1].res;
            BOOST_LOG_TRIVIAL(error) << "io_submit(IOCB_CMD_PREAD): " << strerror(errno);
            break;
          }
          if (events[1].res == 0) {
            BOOST_LOG_TRIVIAL(error) << "[-] edge side EOF\n";
            break;
          }
          cb[0].aio_nbytes = events[1].res;
        }
    }

    void read_handler()
    {
        auto self{shared_from_this()};

        peerSocket_->async_read_some(
            boost::asio::buffer(serverBuffer_, buffer_size_),
            [this, self](const boost::system::error_code &error_code, std::size_t bytes_recvd)
            {
                if(!error_code) {
                    //BOOST_LOG_TRIVIAL(trace) << "SERVER: read some " << bytes_recvd << " bytes from " << peerSocket_->remote_endpoint() << " local " << peerSocket_->local_endpoint();
                    if(bytes_recvd > 0) {
                        boost::asio::async_write(
                            clientSocket_, boost::asio::buffer(serverBuffer_, bytes_recvd),
                            [this, self](const boost::system::error_code& /*ec*/, std::size_t /*bytes_sent*/)
                            {
                                //BOOST_LOG_TRIVIAL(trace) << "SERVER: write " << bytes_sent << " bytes from " << clientSocket_.local_endpoint() << " to " << clientSocket_.remote_endpoint();
                                read_handler();
                            });
                    }
                    else
                    {
                    read_handler();
                    }
                }
                else
                {
                    BOOST_LOG_TRIVIAL(error) << "TCP SERVER error: " << error_code;
                    if(peerSocket_->is_open()) {
                        peerSocket_->close();
                    }
                }
            });
    }

    void readclient_handler()
    {
        auto self{shared_from_this()};

        clientSocket_.async_read_some(
            boost::asio::buffer(clientBuffer_, buffer_size_),
            [this, self](const boost::system::error_code &error_code, std::size_t bytes_recvd)
            {
                if(!error_code) {
                    //BOOST_LOG_TRIVIAL(trace) << "CLIENT: read some " << bytes_recvd << " bytes from " << clientSocket_.remote_endpoint() << " " << clientSocket_.local_endpoint();
                    if(bytes_recvd > 0) {
                        boost::asio::async_write(
                            *peerSocket_, boost::asio::buffer(clientBuffer_, bytes_recvd),
                            [this, self](const boost::system::error_code& /*ec*/, std::size_t /*bytes_sent*/)
                            {
                                //BOOST_LOG_TRIVIAL(trace) << "CLIENT: write " << bytes_sent << " bytes from " << peerSocket_->local_endpoint() << " to " << peerSocket_->remote_endpoint();
                                readclient_handler();
                            });
                    } else {
                        readclient_handler();
                    }
                }
                else
                {
                    BOOST_LOG_TRIVIAL(error) << "TCP CLIENT error: " << error_code;
                    if(clientSocket_.is_open()) {
                        clientSocket_.close();
                    }
                }
            });

    }

private:
    std::shared_ptr<boost::asio::ip::tcp::socket> peerSocket_;
    boost::asio::ip::tcp::socket clientSocket_;
    boost::asio::ip::tcp::endpoint local_endpoint_;
    boost::asio::ip::tcp::endpoint destination_endpoint_;
    std::vector<char> serverBuffer_;
    std::vector<char> clientBuffer_;
    const std::size_t buffer_size_{};
    int sock_map_{};
    Options options_{};
    std::vector<std::thread> runnerThreads_{};
};

TcpRelayServer::TcpRelayServer(
  boost::asio::io_context& io_context,
  const RelayTcpEndpoint& endpoint,
  const std::size_t buffer_size,
  int sock_map,
  Options options) :
    io_context_(io_context),
    local_tcp_acceptor_{io_context, endpoint.localEndpoint()},
    destination_endpoint_{endpoint.destinationEndpoint()},
    buffer_size_(buffer_size),
    sock_map_(sock_map),
    options_(options)
{
}

void TcpRelayServer::start()
{
    const std::shared_ptr<boost::asio::ip::tcp::socket> peerSocket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);

    local_tcp_acceptor_.async_accept(
        *peerSocket,
        [this, peerSocket](const boost::system::error_code& error_code)
        {
            if (!error_code) {
                BOOST_LOG_TRIVIAL(trace) << "TCP: Accept connecton from " << peerSocket->remote_endpoint() << " on " << local_tcp_acceptor_.local_endpoint();
                auto instance = std::make_shared<TcpSession>(
                  io_context_,
                  peerSocket,
                  destination_endpoint_,
                  buffer_size_,
                  sock_map_,
                  options_);
                instance->start();
                sessions_.push_back(instance);
            } else {
                BOOST_LOG_TRIVIAL(error) << "TCP: Error: accept from " << peerSocket->remote_endpoint() << " on " << local_tcp_acceptor_.local_endpoint() << " fails: " << error_code;
            }

            start();
        });
    BOOST_LOG_TRIVIAL(info) << "TCP relay server started on " << local_tcp_acceptor_.local_endpoint();

}

void TcpRelayServer::close()
{
    for(auto i : sessions_) {
    }
    sessions_.clear();
}

boost::asio::ip::tcp::endpoint RelayTcpEndpoint::localEndpoint() const
{
    return localEndpoint_;
}

boost::asio::ip::tcp::endpoint RelayTcpEndpoint::destinationEndpoint() const
{
    return destinationEndpoint_;
}

RelayTcpEndpoint::RelayTcpEndpoint(
  boost::asio::ip::tcp::endpoint localEndpoint,
  boost::asio::ip::tcp::endpoint destinationEnpoint)
  : localEndpoint_{std::move(localEndpoint)}, destinationEndpoint_{std::move(destinationEnpoint)}
{

}

TcpEndpointBuilder TcpEndpointBuilder::build()
{
    return {};
}

TcpEndpointBuilder &TcpEndpointBuilder::withLocalEndpoint(const std::string &address, unsigned short port)
{
    localEndpointAddress_ = address;
    localEndpointPort_ = port;
    return *this;
}

TcpEndpointBuilder &TcpEndpointBuilder::withDestinationEndpoint(const std::string &address, unsigned short port)
{
    destinationEndpointAddress_ = address;
    destinationEndpointPort_ = port;
    return *this;
}

RelayTcpEndpoint TcpEndpointBuilder::create()
{
    const boost::asio::ip::tcp::endpoint destinationEndpoint{boost::asio::ip::address::from_string(destinationEndpointAddress_),
      destinationEndpointPort_};

    const boost::asio::ip::tcp::endpoint localEndpoint{boost::asio::ip::address::from_string(localEndpointAddress_),
      localEndpointPort_};


    return RelayTcpEndpoint{localEndpoint, destinationEndpoint};
}

} // namespace relay
