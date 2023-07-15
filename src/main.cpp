#include <iostream>
#include <errno.h>
#include <csignal>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>
//#include <boost/log/trivial.hpp>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>

#include "UdpRelayServer.hpp"
#include "TcpRelayServer.hpp"

#include "options.hpp"

#include "sockmap.h"
#include "sockmap.skel.h"

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

static const char *LEVEL[] =
    {
        "WARN",
        "INFO",
        "DEBUG"
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    fprintf(stderr, "[libbpf %s]: ", LEVEL[level]);
    return vfprintf(stderr, format, args);
}

int main(int argc, char* argv[])
{
  boost::program_options::options_description desc{"Options"};
    try
    {
        desc.add_options()
            ("help,h", "Help screen")
          ("local_address,a", boost::program_options::value<std::string>()->required(), "Local listen ip")
            ("local_port,l", boost::program_options::value<unsigned short>()->default_value(LOCAL_PORT), "Local listen port")
          ("nat_address,n", boost::program_options::value<std::string>()->required(), "NAT ip address")
            ("buffer_size,b", boost::program_options::value<std::size_t>()->default_value(BUFFER_SIZE), "Buffer size")
          ("destination_ip,i", boost::program_options::value<std::string>()->required(), "Destination IP address")
          ("destination_port,p", boost::program_options::value<unsigned short>()->required(), "Destination port")
            ("relay,r", boost::program_options::value<Options>()->required(), "Relay option")
            ;

        boost::program_options::variables_map variables_map;
        store(parse_command_line(argc, argv, desc), variables_map);

        if (variables_map.count("help") != 0U) {
            std::cout << desc << '\n';
            return EXIT_SUCCESS;
        }

        notify(variables_map);

        Options options = variables_map["relay"].as<Options>();
        auto port = variables_map["local_port"].as<const unsigned short>();
        auto buffer_size = variables_map["buffer_size"].as<const std::size_t>();
        auto localAddress = variables_map["local_address"].as<std::string>();
        auto natAddress = variables_map["nat_address"].as<std::string>();

        struct sockmap socketmaps{};
        if(options == Options::SOCKMAP_RELAY) {
            /* Set up libbpf errors and debug info callback */
            libbpf_set_print(libbpf_print_fn);

            /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
            struct rlimit rlim_new;
            rlim_new.rlim_cur  = RLIM_INFINITY;
            rlim_new.rlim_max  = RLIM_INFINITY;

            if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
                std::cerr << "Failed to increase RLIMIT_MEMLOCK limit!\n";
                return EXIT_FAILURE;
            }

            /* Open BPF application */
            socketmaps.skel = sockmap_bpf__open();
            if (!socketmaps.skel) {
                std::cerr << "Failed to open BPF skeleton\n";
                return EXIT_FAILURE;
            }

            /* Parameterize BPF code with ... */
            //socketmaps.skel....

            /* Load & verify BPF programs */
            int err = sockmap_bpf__load(socketmaps.skel);
            if (err) {
                std::cerr << "Failed to load and verify BPF skeleton\n";
                sockmap_bpf__destroy(socketmaps.skel);
                return EXIT_FAILURE;
            }

            /* Attach tracepoint handler */
            err = sockmap_bpf__attach(socketmaps.skel);
            if (err) {
              std::cerr << "Failed to attach BPF skeleton\n";
              sockmap_bpf__destroy(socketmaps.skel);
              return EXIT_FAILURE;
            }

            /* Attach maps to programs. It's important to attach SOCKMAP
             * to both parser and verdict programs, even though in parser
             * we don't use it. The whole point is to make prog_parser
             * hooked to SOCKMAP.*/
            int sock_map = bpf_object__find_map_fd_by_name(socketmaps.skel->obj, "sock_map");
            bpf_program* bpf_parser = bpf_object__find_program_by_name(socketmaps.skel->obj, "_prog_parser");
            bpf_program* bpf_verdict = bpf_object__find_program_by_name(socketmaps.skel->obj, "_prog_verdict");

            int r = bpf_prog_attach(bpf_program__fd(bpf_parser), sock_map, BPF_SK_SKB_STREAM_PARSER, 0);
            if (r < 0) {
              std::cerr << "bpf(PROG_ATTACH, bpf_parser, sock_map) " << strerror(errno) << '\n';
              return EXIT_FAILURE;
            }

            r = bpf_prog_attach(bpf_program__fd(bpf_verdict), sock_map, BPF_SK_SKB_STREAM_VERDICT, 0);
            if (r < 0) {
              std::cerr << "bpf(PROG_ATTACH, bpf_verdict, sock_map) " << strerror(errno) << '\n';
              return EXIT_FAILURE;
            }
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
    catch (const boost::program_options::required_option& e) {
        std::cerr << "Error: Required option '" << e.get_option_name() << "' is missing.\n";
        std::cout << desc << '\n';
        return EXIT_FAILURE;
    } catch (const boost::program_options::invalid_option_value& e) {
        std::cerr << "Error: Invalid value for option '" << e.get_option_name() << "'.\n";
        std::cout << desc << '\n';
        return EXIT_FAILURE;
    } catch (const boost::program_options::multiple_values& e) {
        std::cerr << "Error: Multiple values provided for option '" << e.get_option_name() << "'.\n";
        std::cout << desc << '\n';
        return EXIT_FAILURE;
    } catch (std::exception& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << boost::current_exception_diagnostic_information();
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
