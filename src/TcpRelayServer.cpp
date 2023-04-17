#include "TcpRelayServer.hpp"

#include <memory>
#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>

namespace relay {

class TcpSession : public std::enable_shared_from_this<TcpSession>
{
public:
  TcpSession(boost::asio::io_context& io_context, std::shared_ptr<boost::asio::ip::tcp::socket> peerSocket, boost::asio::ip::tcp::endpoint destinationEndpoint, const std::size_t buffer_size) :
        peerSocket_{std::move(peerSocket)},
        clientSocket_{io_context},
        destination_endpoint_{std::move(destinationEndpoint)},
        serverBuffer_(buffer_size),
        clientBuffer_(buffer_size),
        buffer_size_(buffer_size)
    {

    }

    void start()
    {
        auto self{shared_from_this()};

        clientSocket_.async_connect(
            destination_endpoint_,
            [this, self](const boost::system::error_code& error_code)
            {
                if (!error_code)
                {
                    BOOST_LOG_TRIVIAL(trace) << "TCP: Connect from " << clientSocket_.local_endpoint() << " to " << destination_endpoint_;
                    readclient_handler();
                    read_handler();
                }
            });

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
};

TcpRelayServer::TcpRelayServer(boost::asio::io_context& io_context,
  const RelayTcpEndpoint& endpoint,
                               const std::size_t buffer_size) :
    io_context_(io_context),
    local_tcp_acceptor_{io_context, endpoint.localEndpoint()},
    destination_endpoint_{endpoint.destinationEndpoint()},
    buffer_size_(buffer_size)
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
                std::make_shared<TcpSession>(io_context_, peerSocket, destination_endpoint_, buffer_size_)->start();
            } else {
                BOOST_LOG_TRIVIAL(error) << "TCP: Error: accept from " << peerSocket->remote_endpoint() << " on " << local_tcp_acceptor_.local_endpoint() << " fails: " << error_code;
            }

            start();
        });
    BOOST_LOG_TRIVIAL(info) << "TCP relay server started on " << local_tcp_acceptor_.local_endpoint();

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
