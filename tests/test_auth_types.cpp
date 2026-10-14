#include <catch2/catch_test_macros.hpp>
#include <yanterm-ssh/auth/types.hpp>

using namespace yanterm::ssh;

using auth::auth_verdict;

TEST_CASE("auth_verdict factories", "[auth][types]") {
    const auto ok = auth_verdict::success();
    REQUIRE(ok.kind == auth::verdict_kind::success);

    const auto no = auth_verdict::failure("publickey,password", true);
    REQUIRE(no.kind == auth::verdict_kind::failure);
    REQUIRE(no.partial_success);
    REQUIRE(no.methods == "publickey,password");

    const auth::kbdint_prompt pr{"pw", false};
    const auto inf = auth_verdict::info("login", "enter pw", std::span{&pr, 1});
    REQUIRE(inf.kind == auth::verdict_kind::info);
    REQUIRE(inf.prompts.size() == 1);
    REQUIRE(inf.prompts[0].prompt == "pw");
    REQUIRE_FALSE(inf.prompts[0].echo);
}
