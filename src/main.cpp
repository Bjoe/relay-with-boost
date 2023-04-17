#include <iostream>
#include <csignal>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>
//#include <boost/log/trivial.hpp>

#include "UdpRelayServer.hpp"
#include "TcpRelayServer.hpp"

constexpr int LOCAL_PORT = 20000;
constexpr int BUFFER_SIZE = 8192;

int main(int argc, char* argv[])
{
    try
    {
        boost::program_options::options_description desc{"Options"};
        desc.add_options()
            ("help,h", "Help screen")
            ("local_address,a", boost::program_options::value<std::string>(), "Local listen ip")
            ("local_port,l", boost::program_options::value<unsigned short>()->default_value(LOCAL_PORT), "Local listen port")
            ("nat_address,n", boost::program_options::value<std::string>(), "NAT ip address")
            ("buffer_size,b", boost::program_options::value<std::size_t>()->default_value(BUFFER_SIZE), "Buffer size")
            ("destination_ip,i", boost::program_options::value<std::string>(), "Destination IP address")
            ("destination_port,p", boost::program_options::value<unsigned short>(), "Destination port")
            ;

        boost::program_options::variables_map variables_map;
        store(parse_command_line(argc, argv, desc), variables_map);
        notify(variables_map);

        if (variables_map.count("help") != 0U) {
            std::cout << desc << '\n';
            return EXIT_SUCCESS;
        }

        if(variables_map.count("local_address") == 0U) {
            std::cerr << "Local IP address is needed." << '\n';
            std::cout << desc << '\n';
            return EXIT_FAILURE;
        }

        if(variables_map.count("nat_address") == 0U) {
            std::cerr << "NAT IP address is needed." << '\n';
            std::cout << desc << '\n';
            return EXIT_FAILURE;
        }

        auto port = variables_map["local_port"].as<const unsigned short>();
        auto buffer_size = variables_map["buffer_size"].as<const std::size_t>();
        auto localAddress = variables_map["local_address"].as<std::string>();
        auto natAddress = variables_map["nat_address"].as<std::string>();

        if(variables_map.count("destination_ip") == 0U) {
            std::cerr << "Destination IP address is needed." << '\n';
            std::cout << desc << '\n';
            return EXIT_FAILURE;
        }

        if(variables_map.count("destination_port") == 0U) {
            std::cerr << "Destination port is needed" << '\n';
            std::cout << desc << '\n';
            return EXIT_FAILURE;
        }

        auto destinationIp = variables_map["destination_ip"].as<std::string>();
        auto destinationPort = variables_map["destination_port"].as<unsigned short>();

        auto relayEndpoint = relay::TcpEndpointBuilder::build()
                               .withDestinationEndpoint(destinationIp, destinationPort)
                               .withLocalEndpoint(localAddress, port)
                               .create();

        auto relayUdpEndpoint = relay::UdpEndpointBuilder::build()
                                  .withDestinationEndpoint(destinationIp, destinationPort)
                                  .withLocalEndpoint(localAddress, port)
                                  .withNatDestinationEndpoint(natAddress)
                                  .create();

        boost::asio::io_context io_context{};
        boost::asio::signal_set signals{io_context, SIGINT, SIGTERM};
        signals.async_wait([&io_context](const boost::system::error_code&, const int&){
            io_context.stop();
        });

        relay::UdpRelayServer server(io_context, relayUdpEndpoint, buffer_size);
        server.do_receive();

        relay::TcpRelayServer tcpServer(io_context, relayEndpoint, buffer_size);
        tcpServer.start();

        io_context.run();
    }
    catch (std::exception& e)
    {
       //BOOST_LOG_TRIVIAL(error) << e.what();
        std::cerr << e.what();
    }
    catch (...)
    {
        //BOOST_LOG_TRIVIAL(error) << boost::current_exception_diagnostic_information();
        std::cerr << boost::current_exception_diagnostic_information();
    }

    return EXIT_SUCCESS;
}
