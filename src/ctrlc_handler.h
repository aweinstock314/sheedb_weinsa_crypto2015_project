#include <cstdlib>
#include <functional>
#include <vector>

class CtrlCHandler {
    public:
    static std::vector<std::function<void()>> cleanup_functions;
    static void cleanup() {
        for(std::function<void()> cleanup_function : cleanup_functions) {
            cleanup_function();
        }
        exit(0);
    }
    static void add_handler(std::function<void()> f) {
        cleanup_functions.push_back(f);
    }
};

std::vector<std::function<void()>> CtrlCHandler::cleanup_functions;

void handle_control_c(int signal) {
    (void)signal; // silence -Wunused-parameter
    CtrlCHandler::cleanup();
}
