//
// Created by Artur Troian on 16.10.2019
//

//Remove Middle Man
//The commented-out block (static_init *instance = instantiate<static_init>()) served no purpose, it was an alternative initialization strategy that was
//abandoned. Leaving dead code commented out is noise; it has been removed.

#include <jwtpp/statics.hh>

namespace jwtpp {

static_init &static_instance = static_init::inst();

} // namespace jwtpp