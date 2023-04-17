#ifndef RELAY_SERVER_HPP
#define RELAY_SERVER_HPP

#include <cstdlib>
#include <memory>
#include <boost/asio.hpp>
#include <boost/array.hpp>

namespace relay {

class UdpEndpointBuilder;

class RelayUdpEndpoint {
public:

  boost::asio::ip::udp::endpoint localEndpoint() const;
  boost::asio::ip::udp::endpoint destinationEndpoint() const;
  boost::asio::ip::udp::endpoint natEndpoint() const;

  friend class UdpEndpointBuilder;
private:
  RelayUdpEndpoint(
    boost::asio::ip::udp::endpoint localEndpoint,
    boost::asio::ip::udp::endpoint destinationEnpoint,
    boost::asio::ip::udp::endpoint natEndpoint);

  boost::asio::ip::udp::endpoint localEndpoint_{};
  boost::asio::ip::udp::endpoint destinationEndpoint_{};
  boost::asio::ip::udp::endpoint natEndpoint_{};
};

class UdpEndpointBuilder {
public:
  static UdpEndpointBuilder build();

  UdpEndpointBuilder& withLocalEndpoint(const std::string& address, unsigned short port);
  UdpEndpointBuilder& withDestinationEndpoint(const std::string& address, unsigned short port);
  UdpEndpointBuilder& withNatDestinationEndpoint(const std::string& address, unsigned short port = 0);

  RelayUdpEndpoint create();
private:
  UdpEndpointBuilder() {};
  std::string localEndpointAddress_{};
  unsigned short localEndpointPort_{};
  std::string destinationEndpointAddress_{};
  unsigned short destinationEndpointPort_{};
  std::string natEndpointAddress_{};
  unsigned short natEndpointPort_{};
};


class UdpRelayServer
{
public:
    UdpRelayServer(boost::asio::io_context& io_context,
                   const RelayUdpEndpoint& udpEndpoint,
                   const std::size_t buffer_size);

    void do_receive();

private:
    boost::asio::ip::udp::socket local_udp_socket_;
    boost::asio::ip::udp::socket nat_udp_socket_;
    boost::asio::ip::udp::endpoint client_endpoint_{};
    boost::asio::ip::udp::endpoint destination_endpoint_;
    boost::asio::ip::udp::endpoint receive_endpoint_;
    std::vector<char> in_buf_;
    std::vector<char> out_buf_;
    const std::size_t buffer_size_{};
    boost::asio::ip::udp::endpoint cli_udp_ep_{};

};

} // namespace relay

#endif // RELAY_SERVER_HPP
