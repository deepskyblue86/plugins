#include "containerd.h"
#include "runc.h"
#include <regex>

using namespace libsinsp::runc;

static const std::regex pattern("/([A-Za-z0-9]+(?:[._-](?:[A-Za-z0-9]+))*)/");

bool containerd::resolve(const std::string& cgroup, std::string& container_id)
{
    // Containers created via ctr
    // use a cgroup path like: `0::/namespace/container_id`
    // Since we cannot know the namespace in advance, we try to
    // extract it from the cgroup path by following provided regex,
    // and use that to eventually extract the container id.
    std::smatch matches;
    if(std::regex_search(cgroup, matches, pattern))
    {
        const auto containerd_namespace{matches[0].str()};
        const cgroup_layout CONTAINERD_CGROUP_LAYOUT[] = {
                {containerd_namespace.c_str(), ""}, {nullptr, nullptr}};
        return matches_runc_cgroup(cgroup, CONTAINERD_CGROUP_LAYOUT,
                                   container_id, true);
    }
    return false;
}