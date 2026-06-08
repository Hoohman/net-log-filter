#include "log_filter.h"

#include <fstream>
#include <iostream>

int main(int argc, char *argv[]) {
  auto filter = create_filter(
      {{"subnet", "192.168.0.0/1"}, {"range", "0.0.0.0-255.255.255.255"}});

  std::ifstream file;

  if (argc > 1) {
    file.open(argv[1]);
    if (!file.is_open()) {
      std::cerr << "Error: cannot open file \"" << argv[1] << "\"\n";
      return 1;
    }
  }

  std::cout << "=== Filtered output ===\n";
  process_stream(file, std::cout, *filter);

  return 0;
}