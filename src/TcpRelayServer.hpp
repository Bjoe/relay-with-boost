#ifndef TCP_RELAY_SERVER_HPP
#define TCP_RELAY_SERVER_HPP

#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/optional.hpp>
#include "options.hpp"

namespace relay {

class TcpEndpointBuilder;

class RelayTcpEndpoint {
public:

  boost::asio::ip::tcp::endpoint localEndpoint() const;
  boost::asio::ip::tcp::endpoint destinationEndpoint() const;

  friend class TcpEndpointBuilder;
private:
  RelayTcpEndpoint(boost::asio::ip::tcp::endpoint localEndpoint, boost::asio::ip::tcp::endpoint destinationEnpoint);
  boost::asio::ip::tcp::endpoint localEndpoint_{};
  boost::asio::ip::tcp::endpoint destinationEndpoint_{};
};

class TcpEndpointBuilder {
public:
  static TcpEndpointBuilder build();

  TcpEndpointBuilder& withLocalEndpoint(const std::string& address, unsigned short port);
  TcpEndpointBuilder& withDestinationEndpoint(const std::string& address, unsigned short port);

  RelayTcpEndpoint create();
private:
  TcpEndpointBuilder() {};
  std::string localEndpointAddress_{};
  unsigned short localEndpointPort_{};
  std::string destinationEndpointAddress_{};
  unsigned short destinationEndpointPort_{};
};

class TcpSession;

class TcpRelayServer
{
public:
  TcpRelayServer(
    boost::asio::io_context& io_context,
    const RelayTcpEndpoint &endpoint,
    const std::size_t buffer_size,
    int sock_map,
    Options options);

    void start();

    void close();
private:
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor local_tcp_acceptor_;
    boost::asio::ip::tcp::endpoint destination_endpoint_;
    const std::size_t buffer_size_{};
    int sock_map_{};
    Options options_{};
    std::vector<std::shared_ptr<TcpSession>> sessions_;
};

} // namespace relay

#endif // TCP_RELAY_SERVER_HPP
