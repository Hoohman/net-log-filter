#include "log_filter.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

// ─── helpers
// ──────────────────────────────────────────────────────────────────

namespace {
int passed = 0;
int failed = 0;
} // namespace

static void check(const char *name, bool expr) {
  if (expr) {
    ++passed;
    std::cout << "[OK] " << name << "\n";
  } else {
    ++failed;
    std::cout << "[FAIL] " << name << "\n";
  }
}

static uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | d;
}

// ─── parse_ipv4
// ───────────────────────────────────────────────────────────────

static void test_parse_ipv4() {
  // valid
  check("parse 192.168.1.25",
        parse_ipv4("192.168.1.25") == ip(192, 168, 1, 25));
  check("parse 10.0.0.1", parse_ipv4("10.0.0.1") == ip(10, 0, 0, 1));

  // edge cases
  check("parse 0.0.0.0", parse_ipv4("0.0.0.0") == ip(0, 0, 0, 0));
  check("parse 255.255.255.255",
        parse_ipv4("255.255.255.255") == ip(255, 255, 255, 255));

  // invalid
  check("reject octet > 255", !parse_ipv4("192.168.1.256"));
  check("reject incomplete", !parse_ipv4("192.168.1"));
  check("reject alpha", !parse_ipv4("invalid.ip"));
  check("reject empty", !parse_ipv4(""));
  check("reject too many dots", !parse_ipv4("1.2.3.4.5"));
  check("reject leading dot", !parse_ipv4(".1.2.3.4"));
}

// ─── filters
// ──────────────────────────────────────────────────────────────────

static void test_subnet_filter() {
  // 192.168.0.0/24  ->  192.168.0.0 – 192.168.0.255
  auto cidr = parse_cidr("192.168.0.0/24");
  assert(cidr.has_value());
  SubnetFilter f(cidr->first, cidr->second);

  check("subnet: inside", f.match(ip(192, 168, 0, 1)));
  check("subnet: network addr", f.match(ip(192, 168, 0, 0)));
  check("subnet: broadcast addr", f.match(ip(192, 168, 0, 255)));
  check("subnet: outside", !f.match(ip(192, 168, 1, 1)));
}

static void test_range_filter() {
  auto rng = parse_range("10.0.0.1-10.0.0.100");
  assert(rng.has_value());
  RangeFilter f(rng->first, rng->second);

  check("range: lower bound", f.match(ip(10, 0, 0, 1)));
  check("range: upper bound", f.match(ip(10, 0, 0, 100)));
  check("range: inside", f.match(ip(10, 0, 0, 50)));
  check("range: below lower", !f.match(ip(10, 0, 0, 0)));
  check("range: above upper", !f.match(ip(10, 0, 0, 101)));

  // whole address space
  RangeFilter full(ip(0, 0, 0, 0), ip(255, 255, 255, 255));
  check("range: 0.0.0.0 in full", full.match(ip(0, 0, 0, 0)));
  check("range: 255.255.255.255 in full", full.match(ip(255, 255, 255, 255)));
}

static void test_composite_filter() {
  // subnet 192.168.0.0/24 AND range 192.168.0.10-192.168.0.20
  auto composite = create_filter(
      {{"subnet", "192.168.0.0/24"}, {"range", "192.168.0.10-192.168.0.20"}});

  check("composite: inside both", composite->match(ip(192, 168, 0, 15)));
  check("composite: in subnet only", !composite->match(ip(192, 168, 0, 5)));
  check("composite: outside both", !composite->match(ip(10, 0, 0, 1)));
}

// ─── process_stream
// ───────────────────────────────────────────────────────────

static void test_process_stream() {
  std::string input_data = "192.168.0.5 - GET /\n"
                           "10.0.0.1 - POST /login\n"
                           "192.168.1.256 - INVALID\n"
                           "invalid.ip - CORRUPTED\n"
                           " - EMPTY\n"
                           "192.168.0.200 - GET /api\n";

  std::istringstream input(input_data);
  std::ostringstream output;

  auto filter = create_filter({{"subnet", "192.168.0.0/24"}});
  process_stream(input, output, *filter);

  std::string result = output.str();
  check("stream: passes 192.168.0.5",
        result.find("192.168.0.5") != std::string::npos);
  check("stream: passes 192.168.0.200",
        result.find("192.168.0.200") != std::string::npos);
  check("stream: drops 10.0.0.1", result.find("10.0.0.1") == std::string::npos);
  check("stream: drops invalid data",
        result.find("INVALID") == std::string::npos);
  check("stream: drops corrupted",
        result.find("CORRUPTED") == std::string::npos);
}

// ─── main
// ─────────────────────────────────────────────────────────────────────

int main() {
  test_parse_ipv4();
  test_subnet_filter();
  test_range_filter();
  test_composite_filter();
  test_process_stream();

  std::cout << "\n" << passed << " passed, " << failed << " failed\n";
  return failed == 0 ? 0 : 1;
}
