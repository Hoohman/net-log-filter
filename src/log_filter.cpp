#include "log_filter.h"

#include <cstddef>
#include <cstdint>
#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

SubnetFilter::SubnetFilter(uint32_t ip, uint32_t mask) : ip_(ip), mask_(mask) {}

bool SubnetFilter::match(uint32_t ip) const {
  return (ip & mask_) == (ip_ & mask_);
}

RangeFilter::RangeFilter(uint32_t start_ip, uint32_t end_ip)
    : start_ip_(start_ip), end_ip_(end_ip) {}

bool RangeFilter::match(uint32_t ip) const {
  return ip >= start_ip_ && ip <= end_ip_;
}

bool CompositeFilter::match(uint32_t ip) const {
  for (size_t i = 0; i < filters_.size(); i++) {
    if (bool filter = filters_[i]->match(ip); !filter) {
      return false;
    }
  }
  return true;
}

void CompositeFilter::add_filter(std::unique_ptr<IFilter> filter) {
  filters_.push_back(std::move(filter));
}

std::unique_ptr<CompositeFilter>
create_filter(const std::vector<FilterRule> &filters) {
  if (filters.size() > 20) {
    throw std::invalid_argument("Too many rules: max 20 allowed");
  }

  auto composite = std::make_unique<CompositeFilter>();

  for (const auto &filter : filters) {
    if (filter.type == "subnet") {
      auto cidr_opt = parse_cidr(filter.value);
      if (!cidr_opt) {
        throw std::invalid_argument("Invalid subnet format: " + filter.value);
      }

      composite->add_filter(
          std::make_unique<SubnetFilter>(cidr_opt->first, cidr_opt->second));
    } else if (filter.type == "range") {
      auto range_opt = parse_range(filter.value);
      if (!range_opt) {
        throw std::invalid_argument("Invalid range format: " + filter.value);
      }

      composite->add_filter(
          std::make_unique<RangeFilter>(range_opt->first, range_opt->second));
    } else {
      throw std::invalid_argument("Unknown filter type: " + filter.type);
    }
  }

  return composite;
}

void process_stream(std::istream &input, std::ostream &output,
                    const IFilter &filter) {
  std::vector<std::string> buffer;
  buffer.reserve(1000);
  std::string line;

  while (std::getline(input, line)) {
    buffer.push_back(std::move(line));

    if (buffer.size() == 1000) {
      process_buffer(buffer, filter, output);
      buffer.clear();
    }
  }

  if (!buffer.empty()) {
    process_buffer(buffer, filter, output);
  }
}

std::optional<uint32_t> parse_ipv4(std::string_view line) {
  uint32_t result = 0;
  int current_octet = 0;
  int octet_count = 0;
  bool has_digit = false;

  for (char c : line) {
    if (c >= '0' && c <= '9') {
      current_octet = (current_octet * 10) + (c - '0');
      has_digit = true;

      if (current_octet > 255) {
        return std::nullopt;
      }
    } else if (c == '.') {
      if (!has_digit || octet_count >= 3) {
        return std::nullopt;
      }

      result = (result << 8) | current_octet;

      current_octet = 0;
      octet_count++;
      has_digit = false;
    } else {
      return std::nullopt;
    }
  }

  if (!has_digit || octet_count != 3) {
    return std::nullopt;
  }

  result = (result << 8) | current_octet;
  return result;
}

std::optional<std::pair<uint32_t, uint32_t>>
parse_cidr(std::string_view value) {
  size_t slash = value.find('/');
  if (slash == std::string_view::npos) {
    return std::nullopt;
  }

  auto ip_opt = parse_ipv4(value.substr(0, slash));
  if (!ip_opt) {
    return std::nullopt;
  }
  uint32_t ip = ip_opt.value();

  std::string_view prefix_str = value.substr(slash + 1);
  if (prefix_str.empty()) {
    return std::nullopt;
  }

  int prefix = 0;
  for (char c : prefix_str) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    prefix = (prefix * 10) + (c - '0');

    if (prefix > 32) {
      return std::nullopt;
    }
  }

  uint32_t mask = 0;
  if (prefix > 0) {
    mask = ~0U << (32 - prefix);
  }

  return std::make_pair(ip, mask);
}

std::optional<std::pair<uint32_t, uint32_t>>
parse_range(std::string_view value) {
  size_t dash_pos = value.find('-');
  if (dash_pos == std::string_view::npos) {
    return std::nullopt;
  }

  auto start_opt = parse_ipv4(value.substr(0, dash_pos));

  auto end_opt = parse_ipv4(value.substr(dash_pos + 1));

  if (!start_opt || !end_opt) {
    return std::nullopt;
  }

  uint32_t start_ip = start_opt.value();
  uint32_t end_ip = end_opt.value();

  if (start_ip > end_ip) {
    return std::nullopt;
  }

  return std::make_pair(start_ip, end_ip);
}

void process_buffer(std::span<const std::string> buffer, const IFilter &filter,
                    std::ostream &output) {
  for (const auto &line : buffer) {
    size_t space = line.find(' ');
    std::string_view ip_adr = line.substr(0, space);

    if (ip_adr.empty()) {
      continue;
    }

    auto ip_opt = parse_ipv4(ip_adr);

    if (ip_opt && filter.match(ip_opt.value())) {
      output << line << "\n";
    }
  }
}