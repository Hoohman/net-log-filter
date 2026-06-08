#pragma once

#include <cstdint>
#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct FilterRule {
  std::string type;
  std::string value;
};

class IFilter {
public:
  virtual bool match(uint32_t ip) const = 0;
  virtual ~IFilter() = default;
};

class SubnetFilter : public IFilter {
public:
  SubnetFilter(uint32_t ip, uint32_t mask);
  bool match(uint32_t ip) const override;

private:
  uint32_t ip_;
  uint32_t mask_;
};

class RangeFilter : public IFilter {
public:
  RangeFilter(uint32_t start_ip, uint32_t end_ip);
  bool match(uint32_t ip) const override;

private:
  uint32_t start_ip_;
  uint32_t end_ip_;
};

class CompositeFilter : public IFilter {
public:
  bool match(uint32_t ip) const override;
  void add_filter(std::unique_ptr<IFilter> filter);

private:
  std::vector<std::unique_ptr<IFilter>> filters_;
};

std::unique_ptr<CompositeFilter>
create_filter(const std::vector<FilterRule> &filters);

void process_stream(std::istream &input, std::ostream &output,
                    const IFilter &filter);

std::optional<uint32_t> parse_ipv4(std::string_view line);

std::optional<std::pair<uint32_t, uint32_t>> parse_cidr(std::string_view value);

std::optional<std::pair<uint32_t, uint32_t>>
parse_range(std::string_view value);

void process_buffer(std::span<const std::string> buffer, const IFilter &filter,
                    std::ostream &output);
