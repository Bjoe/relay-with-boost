#include <iostream>
#include <csignal>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>
//#include <boost/log/trivial.hpp>

#include "UdpRelayServer.hpp"
#include "TcpRelayServer.hpp"

#include "options.hpp"

#include <linux/bpf.h>
#include <sys/resource.h>
extern "C" {
#include "sockmap/tbpf.h"
};
#include "sockmap.h"

constexpr int LOCAL_PORT = 20000;
constexpr int BUFFER_SIZE = 8192;

extern size_t bpf_insn_prog_parser_cnt;
extern struct bpf_insn bpf_insn_prog_parser[];
extern struct tbpf_reloc bpf_reloc_prog_parser[];

extern size_t bpf_insn_prog_verdict_cnt;
extern struct bpf_insn bpf_insn_prog_verdict[];
extern struct tbpf_reloc bpf_reloc_prog_verdict[];

std::istream& operator>>(std::istream& in, Options& options)
{
  std::string token;
  in >> token;
  if (token == "tcp")
    options = Options::TCP_RELAY;
  else if (token == "iosubmit")
    options = Options::IOSUBMIT_RELAY;
  else if (token == "splice")
    options = Options::SPLICE_RELAY;
  else if (token == "sockmap")
    options = Options::SOCKMAP_RELAY;
  else
    in.setstate(std::ios_base::failbit);
  return in;
}

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
            ("relay,r", boost::program_options::value<Options>()->required(), "Relay option")
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

        Options options = variables_map["relay"].as<Options>();
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

        struct sockmap socketmaps{};
        if(options == Options::SOCKMAP_RELAY) {
            /*
             * Initialize ebpf
             */
            /* [*] SOCKMAP requires more than 16MiB of locked mem */
            struct rlimit rlim;
            rlim.rlim_cur = 128 * 1024 * 1024;
            rlim.rlim_max = 128 * 1024 * 1024;

            /* ignore error */
            setrlimit(RLIMIT_MEMLOCK, &rlim);

            /* [*] Prepare ebpf */
            socketmaps.sock_map = tbpf_create_map(BPF_MAP_TYPE_SOCKMAP, sizeof(int),
              sizeof(int), socketmaps.max_keys, 0);
            if (socketmaps.sock_map < 0) {
              std::cerr << "bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_SOCKMAP)\n";
              return EXIT_FAILURE;
            }

            socketmaps.port_map = tbpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int),
                                       sizeof(int), socketmaps.max_keys, 0);
            if (socketmaps.port_map < 0) {
              std::cerr << "bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_HASH)\n";
              return EXIT_FAILURE;
            }

            socketmaps.arr_map = tbpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int),
                                                  sizeof(int), 1, 0);
            if (socketmaps.arr_map < 0) {
              std::cerr << "bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_HASH)\n";
              return EXIT_FAILURE;
            }

            /* sockmap is only used in prog_verdict */
            tbpf_fill_symbol(bpf_insn_prog_verdict, bpf_reloc_prog_verdict,
              "sock_map", socketmaps.sock_map);
            tbpf_fill_symbol(bpf_insn_prog_verdict, bpf_reloc_prog_verdict,
              "port_map", socketmaps.port_map);
            tbpf_fill_symbol(bpf_insn_prog_verdict, bpf_reloc_prog_verdict,
                             "arr_map", socketmaps.arr_map);

            /* Load prog_parser and prog_verdict */
            char log_buf[16 * 1024];
            int bpf_parser = tbpf_load_program(
              BPF_PROG_TYPE_SK_SKB, bpf_insn_prog_parser,
              bpf_insn_prog_parser_cnt, "Dual BSD/GPL",
              KERNEL_VERSION(4, 4, 0), log_buf, sizeof(log_buf));
            if (bpf_parser < 0) {
              std::cerr << "Bpf Log:\n" << log_buf << "\n bpf(BPF_PROG_LOAD, prog_parser)\n";
              return EXIT_FAILURE;
            }

            int bpf_verdict = tbpf_load_program(
              BPF_PROG_TYPE_SK_SKB, bpf_insn_prog_verdict,
              bpf_insn_prog_verdict_cnt, "Dual BSD/GPL",
              KERNEL_VERSION(4, 4, 0), log_buf, sizeof(log_buf));
            if (bpf_verdict < 0) {
              std::cerr << "Bpf Log:\n" << log_buf << "\n bpf(BPF_PROG_LOAD, prog_verdict)\n";
              return EXIT_FAILURE;
            }

            /* Attach maps to programs. It's important to attach SOCKMAP
             * to both parser and verdict programs, even though in parser
             * we don't use it. The whole point is to make prog_parser
             * hooked to SOCKMAP.*/
            int r = tbpf_prog_attach(bpf_parser, socketmaps.sock_map, BPF_SK_SKB_STREAM_PARSER,
              0);
            if (r < 0) {
              std::cerr << "bpf(PROG_ATTACH)\n";
              return EXIT_FAILURE;
            }

            r = tbpf_prog_attach(bpf_verdict, socketmaps.sock_map, BPF_SK_SKB_STREAM_VERDICT,
                                 0);
            if (r < 0) {
              std::cerr << "bpf(PROG_ATTACH)\n";
              return EXIT_FAILURE;
            }
//            r = tbpf_prog_attach(bpf_verdict, socketmaps.port_map, BPF_SK_SKB_STREAM_VERDICT,
//                                 0);
//            if (r < 0) {
//              std::cerr << "bpf(PROG_ATTACH)\n";
//              return EXIT_FAILURE;
//            }
            /*************************************************************************/
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

        relay::TcpRelayServer tcpServer(io_context, relayEndpoint, buffer_size, socketmaps, options);
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
