#include "UdpRelayServer.hpp"

#include <memory>
#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>

namespace relay {

UdpEndpointBuilder UdpEndpointBuilder::build()
{
  return {};
}

UdpEndpointBuilder &UdpEndpointBuilder::withLocalEndpoint(const std::string &address, unsigned short port)
{
  localEndpointAddress_ = address;
  localEndpointPort_ = port;
  return *this;
}

UdpEndpointBuilder &UdpEndpointBuilder::withDestinationEndpoint(const std::string &address, unsigned short port)
{
  destinationEndpointAddress_ = address;
  destinationEndpointPort_ = port;
  return *this;
}

UdpEndpointBuilder &UdpEndpointBuilder::withNatDestinationEndpoint(const std::string &address, unsigned short port)
{
  natEndpointAddress_ = address;
  natEndpointPort_ = port;
  return *this;
}

RelayUdpEndpoint UdpEndpointBuilder::create()
{
  const boost::asio::ip::udp::endpoint localEndpoint{boost::asio::ip::address::from_string(localEndpointAddress_), localEndpointPort_};
  const boost::asio::ip::udp::endpoint destinationEndpoint{boost::asio::ip::address::from_string(destinationEndpointAddress_), destinationEndpointPort_};
  const boost::asio::ip::udp::endpoint natEndpoint{boost::asio::ip::address::from_string(natEndpointAddress_), natEndpointPort_};

  return { localEndpoint, destinationEndpoint, natEndpoint };
}

boost::asio::ip::udp::endpoint RelayUdpEndpoint::localEndpoint() const
{
  return localEndpoint_;
}

boost::asio::ip::udp::endpoint RelayUdpEndpoint::destinationEndpoint() const
{
  return destinationEndpoint_;
}

boost::asio::ip::udp::endpoint RelayUdpEndpoint::natEndpoint() const
{
  return natEndpoint_;
}

RelayUdpEndpoint::RelayUdpEndpoint(
  boost::asio::ip::udp::endpoint localEndpoint,
  boost::asio::ip::udp::endpoint destinationEnpoint,
  boost::asio::ip::udp::endpoint natEndpoint)
  : localEndpoint_(std::move(localEndpoint)),
    destinationEndpoint_(std::move(destinationEnpoint)),
    natEndpoint_(std::move(natEndpoint))
{

}

UdpRelayServer::UdpRelayServer(boost::asio::io_context& io_context,
                               const RelayUdpEndpoint &udpEndpoint,
                               const std::size_t buffer_size) :
    local_udp_socket_{io_context, udpEndpoint.localEndpoint()},
    nat_udp_socket_{io_context, udpEndpoint.natEndpoint()},
    destination_endpoint_{udpEndpoint.destinationEndpoint()},
    in_buf_(buffer_size),
    out_buf_(buffer_size),
    buffer_size_{buffer_size}
{
}

void UdpRelayServer::do_receive() {

    local_udp_socket_.async_receive_from(
        boost::asio::buffer(in_buf_, buffer_size_), receive_endpoint_,
        [this](boost::system::error_code error_code, std::size_t bytes_recvd)
        {
            if (!error_code && bytes_recvd > 0)
            {
                //BOOST_LOG_TRIVIAL(trace) << "UDP receive some " << bytes_recvd << " bytes from " << receive_endpoint_ << " via " << local_udp_socket_->local_endpoint();
                client_endpoint_ = receive_endpoint_;
                nat_udp_socket_.async_send_to(
                    boost::asio::buffer(in_buf_, bytes_recvd), destination_endpoint_,
                    [this](boost::system::error_code /*ec*/, std::size_t /*bytes_recvd*/)
                    {
                        //BOOST_LOG_TRIVIAL(trace) << "UDP send " << bytes_recvd << " bytes via " << nat_udp_socket_.local_endpoint() << " to " << destination_endpoint_;
                        do_receive();
                    });
            } else {
                do_receive();
            }
        });

    nat_udp_socket_.async_receive_from(
        boost::asio::buffer(out_buf_, buffer_size_), receive_endpoint_,
        [this](boost::system::error_code error_code, std::size_t bytes_recvd)
        {
            if (!error_code && bytes_recvd > 0)
            {
                //BOOST_LOG_TRIVIAL(trace) << "UDP receive some " << bytes_recvd << " bytes from " << receive_endpoint_ << " via " << nat_udp_socket_.local_endpoint();
                local_udp_socket_.async_send_to(
                    boost::asio::buffer(out_buf_, bytes_recvd), client_endpoint_,
                    [this](boost::system::error_code /*ec*/, std::size_t /*bytes_recvd*/)
                    {
                        //BOOST_LOG_TRIVIAL(trace) << "UDP send some " << bytes_recvd << " bytes via " << local_udp_socket_->local_endpoint() << " to " << client_endpoint_;
                        do_receive();
                    });
            } else {
                do_receive();
            }
      });
}




} // namespace relay
