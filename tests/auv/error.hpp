#ifndef AUV_ERROR_HPP_
#define AUV_ERROR_HPP_

#include <string>
#include <system_error>
#include <type_traits>

namespace auv {

enum class errc { eof = 1 };

struct error_category : std::error_category {
    const char *name() const noexcept override { return "auv"; }

    std::string message(int err) const override {
        switch (static_cast<errc>(err)) {
        case errc::eof:
            return "end of file";
        }
        return "unknown error";
    }

    static const error_category &instance() {
        static const error_category category;
        return category;
    }
};

inline std::error_code make_error_code(errc err) {
    return std::error_code(static_cast<int>(err), error_category::instance());
}

inline std::error_condition make_error_condition(errc err) {
    return std::error_condition(static_cast<int>(err), error_category::instance());
}

} // namespace auv

template <>
struct std::is_error_condition_enum<auv::errc> : std::true_type {};

#endif
