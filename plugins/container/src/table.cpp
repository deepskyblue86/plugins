#include "plugin.h"
#include "container_type.h"
#include <array>
#include <string_view>

constexpr std::string_view CONTAINER_TABLE_NAME{"containers"};

namespace FIELD_STR
{
constexpr std::string_view ID{"id"};
constexpr std::string_view NAME{"name"};
constexpr std::string_view TYPE{"type"};
constexpr std::string_view IMAGE{"image"};
constexpr std::string_view IMAGEID{"imageid"};
constexpr std::string_view IMAGEREPO{"imagerepo"};
constexpr std::string_view IMAGETAG{"imagetag"};
constexpr std::string_view IMAGEDIGEST{"imagedigest"};
constexpr std::string_view CPU_SHARES{"cpu_shares"};
constexpr std::string_view MEMORY_LIMIT{"memory_limit"};
constexpr std::string_view CPU_QUOTA{"cpu_quota"};
constexpr std::string_view CPU_PERIOD{"cpu_period"};
constexpr std::string_view IP{"ip"};
constexpr std::string_view USER{"user"};
constexpr std::string_view CREATED_TIME{"created_time"};
constexpr std::string_view PRIVILEGED{"privileged"};
constexpr std::string_view HOST_PID{"host_pid"};
constexpr std::string_view HOST_NETWORK{"host_network"};
constexpr std::string_view HOST_IPC{"host_ipc"};
constexpr std::string_view IS_POD_SANDBOX{"is_pod_sandbox"};
} // namespace FIELD_STR

enum class FIELD_IDX : uintptr_t
{
    ID = 0,
    NAME,
    TYPE,
    IMAGE,
    IMAGEID,
    IMAGEREPO,
    IMAGETAG,
    IMAGEDIGEST,
    CPU_SHARES,
    MEMORY_LIMIT,
    CPU_QUOTA,
    CPU_PERIOD,
    IP,
    USER,
    CREATED_TIME,
    PRIVILEGED,
    HOST_PID,
    HOST_NETWORK,
    HOST_IPC,
    IS_POD_SANDBOX,
    MAX
};

using namespace falcosecurity::_internal;

// Field definitions using modern C++ array initialization
static constexpr std::array<ss_plugin_table_fieldinfo,
                            static_cast<std::size_t>(FIELD_IDX::MAX)>
        FIELD_DEFINITIONS = {
                {{FIELD_STR::ID.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::NAME.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::TYPE.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::IMAGE.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::IMAGEID.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::IMAGEREPO.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::IMAGETAG.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::IMAGEDIGEST.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::CPU_SHARES.data(), SS_PLUGIN_ST_INT64, true},
                 {FIELD_STR::MEMORY_LIMIT.data(), SS_PLUGIN_ST_INT64, true},
                 {FIELD_STR::CPU_QUOTA.data(), SS_PLUGIN_ST_INT64, true},
                 {FIELD_STR::CPU_PERIOD.data(), SS_PLUGIN_ST_INT64, true},
                 {FIELD_STR::IP.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::USER.data(), SS_PLUGIN_ST_STRING, true},
                 {FIELD_STR::CREATED_TIME.data(), SS_PLUGIN_ST_INT64, true},
                 {FIELD_STR::PRIVILEGED.data(), SS_PLUGIN_ST_BOOL, true},
                 {FIELD_STR::HOST_PID.data(), SS_PLUGIN_ST_BOOL, true},
                 {FIELD_STR::HOST_NETWORK.data(), SS_PLUGIN_ST_BOOL, true},
                 {FIELD_STR::HOST_IPC.data(), SS_PLUGIN_ST_BOOL, true},
                 {FIELD_STR::IS_POD_SANDBOX.data(), SS_PLUGIN_ST_BOOL, true}}};

// Use array directly - no memory copying needed

static ss_plugin_rc read_field(const container_info* ctr, FIELD_IDX field_id,
                               ss_plugin_state_data* out)
{
    switch(field_id)
    {
    case FIELD_IDX::ID:
        out->str = ctr->m_id.c_str();
        break;
    case FIELD_IDX::NAME:
        out->str = ctr->m_name.c_str();
        break;
    case FIELD_IDX::TYPE:
        out->str = to_string(ctr->m_type);
        break;
    case FIELD_IDX::IMAGE:
        out->str = ctr->m_image.c_str();
        break;
    case FIELD_IDX::IMAGEID:
        out->str = ctr->m_imageid.c_str();
        break;
    case FIELD_IDX::IMAGEREPO:
        out->str = ctr->m_imagerepo.c_str();
        break;
    case FIELD_IDX::IMAGETAG:
        out->str = ctr->m_imagetag.c_str();
        break;
    case FIELD_IDX::IMAGEDIGEST:
        out->str = ctr->m_imagedigest.c_str();
        break;
    case FIELD_IDX::CPU_SHARES:
        out->s64 = ctr->m_cpu_shares;
        break;
    case FIELD_IDX::MEMORY_LIMIT:
        out->s64 = ctr->m_memory_limit;
        break;
    case FIELD_IDX::CPU_QUOTA:
        out->s64 = ctr->m_cpu_quota;
        break;
    case FIELD_IDX::CPU_PERIOD:
        out->s64 = ctr->m_cpu_period;
        break;
    case FIELD_IDX::IP:
        out->str = ctr->m_container_ip.c_str();
        break;
    case FIELD_IDX::USER:
        out->str = ctr->m_container_user.c_str();
        break;
    case FIELD_IDX::CREATED_TIME:
        out->s64 = ctr->m_created_time;
        break;
    case FIELD_IDX::PRIVILEGED:
        out->b = ctr->m_privileged;
        break;
    case FIELD_IDX::HOST_PID:
        out->b = ctr->m_host_pid;
        break;
    case FIELD_IDX::HOST_NETWORK:
        out->b = ctr->m_host_network;
        break;
    case FIELD_IDX::HOST_IPC:
        out->b = ctr->m_host_ipc;
        break;
    case FIELD_IDX::IS_POD_SANDBOX:
        out->b = ctr->m_is_pod_sandbox;
        break;
    default:
        return SS_PLUGIN_FAILURE;
    }
    return SS_PLUGIN_SUCCESS;
}

static const char* reader_get_table_name(ss_plugin_table_t* t)
{
    return CONTAINER_TABLE_NAME.data();
}

static uint64_t reader_get_table_size(ss_plugin_table_t* t)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    return containers->size();
}

static ss_plugin_table_entry_t*
reader_get_table_entry(ss_plugin_table_t* t, const ss_plugin_state_data* key)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    if(containers->count(key->str) == 0)
    {
        return nullptr;
    }
    return (ss_plugin_table_entry_t*)containers->at(key->str).get();
}

static ss_plugin_rc reader_read_entry_field(ss_plugin_table_t* t,
                                            ss_plugin_table_entry_t* e,
                                            const ss_plugin_table_field_t* f,
                                            ss_plugin_state_data* out)
{
    auto ctr = static_cast<const container_info*>(e);

    // Convert field pointer to field ID (offset by 1 to avoid NULL)
    auto field_id = static_cast<FIELD_IDX>((uintptr_t)f - 1);

    return read_field(ctr, field_id, out);
}

static void reader_release_table_entry(ss_plugin_table_t* t,
                                       ss_plugin_table_entry_t* e)
{
    // Unsupported for now.
}

static ss_plugin_bool
reader_iterate_entries(ss_plugin_table_t* t,
                       ss_plugin_table_iterator_func_t func,
                       ss_plugin_table_iterator_state_t* s)
{
    auto* containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);

    bool ret{true};
    for(const auto& [_, container] : *containers)
    {
        ret = func(s, (ss_plugin_table_entry_t*)container.get());
        if(!ret)
        {
            break;
        }
    }
    return ret;
}

static const ss_plugin_table_fieldinfo* list_table_fields(ss_plugin_table_t* t,
                                                          uint32_t* nfields)
{
    *nfields = FIELD_DEFINITIONS.size();
    return FIELD_DEFINITIONS.data();
}

static ss_plugin_table_field_t* get_table_field(ss_plugin_table_t* t,
                                                const char* name,
                                                ss_plugin_state_type data_type)
{
    for(unsigned long i = 0; i < FIELD_DEFINITIONS.size(); i++)
    {
        if(strcmp(FIELD_DEFINITIONS[i].name, name) == 0)
        {
            // note: shifted by 1 so that we never return 0 (interpreted as
            // NULL)
            return (ss_plugin_table_field_t*)(i + 1);
        }
    }
    return nullptr;
}

static ss_plugin_table_field_t* add_table_field(ss_plugin_table_t* _t,
                                                const char* name,
                                                ss_plugin_state_type data_type)
{
    // Unsupported for now.
    return nullptr;
}

static ss_plugin_rc clear_table(ss_plugin_table_t* t)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    containers->clear();
    return SS_PLUGIN_SUCCESS;
}

static ss_plugin_rc erase_table_entry(ss_plugin_table_t* t,
                                      const ss_plugin_state_data* key)
{
    auto containers = static_cast<std::unordered_map<
            std::string, std::shared_ptr<const container_info>>*>(t);
    if(containers->count(key->str) == 0)
    {
        return SS_PLUGIN_FAILURE;
    }
    containers->erase(key->str);
    return SS_PLUGIN_SUCCESS;
}

static ss_plugin_table_entry_t* create_table_entry(ss_plugin_table_t* t)
{
    // Unsupported for now.
    return nullptr;
}

static void destroy_table_entry(ss_plugin_table_t* t,
                                ss_plugin_table_entry_t* e)
{
    // Unsupported for now.
}

static ss_plugin_table_entry_t* add_table_entry(ss_plugin_table_t* t,
                                                const ss_plugin_state_data* key,
                                                ss_plugin_table_entry_t* e)
{
    // Unsupported for now.
    return nullptr;
}

static ss_plugin_rc write_entry_field(ss_plugin_table_t* _t,
                                      ss_plugin_table_entry_t* _e,
                                      const ss_plugin_table_field_t* _f,
                                      const ss_plugin_state_data* in)
{
    // Unsupported for now.
    return SS_PLUGIN_NOT_SUPPORTED;
}

static ss_plugin_table_reader_vtable_ext* get_reader_ext()
{
    static ss_plugin_table_reader_vtable_ext reader_vtable;
    reader_vtable.get_table_name = reader_get_table_name;
    reader_vtable.get_table_size = reader_get_table_size;
    reader_vtable.get_table_entry = reader_get_table_entry;
    reader_vtable.read_entry_field = reader_read_entry_field;
    reader_vtable.release_table_entry = reader_release_table_entry;
    reader_vtable.iterate_entries = reader_iterate_entries;
    return &reader_vtable;
}

static ss_plugin_table_fields_vtable_ext* get_fields_ext()
{
    static ss_plugin_table_fields_vtable_ext fields_vtable;
    fields_vtable.list_table_fields = list_table_fields;
    fields_vtable.add_table_field = add_table_field;
    fields_vtable.get_table_field = get_table_field;
    return &fields_vtable;
}

static ss_plugin_table_writer_vtable_ext* get_writer_ext()
{
    static ss_plugin_table_writer_vtable_ext writer_vtable;
    writer_vtable.clear_table = clear_table;
    writer_vtable.erase_table_entry = erase_table_entry;
    writer_vtable.create_table_entry = create_table_entry;
    writer_vtable.destroy_table_entry = destroy_table_entry;
    writer_vtable.add_table_entry = add_table_entry;
    writer_vtable.write_entry_field = write_entry_field;

    return &writer_vtable;
}

ss_plugin_table_input& my_plugin::get_table()
{
    using st = falcosecurity::state_value_type;

    static ss_plugin_table_input input;
    input.name = CONTAINER_TABLE_NAME.data();
    input.key_type = st::SS_PLUGIN_ST_STRING;
    input.table = (void*)&m_containers;

    input.reader_ext = get_reader_ext();
    input.reader.get_table_name = input.reader_ext->get_table_name;
    input.reader.get_table_size = input.reader_ext->get_table_size;
    input.reader.get_table_entry = input.reader_ext->get_table_entry;
    input.reader.read_entry_field = input.reader_ext->read_entry_field;

    input.writer_ext = get_writer_ext();
    input.writer.clear_table = input.writer_ext->clear_table;
    input.writer.erase_table_entry = input.writer_ext->erase_table_entry;
    input.writer.create_table_entry = input.writer_ext->create_table_entry;
    input.writer.destroy_table_entry = input.writer_ext->destroy_table_entry;
    input.writer.add_table_entry = input.writer_ext->add_table_entry;
    input.writer.write_entry_field = input.writer_ext->write_entry_field;

    input.fields_ext = get_fields_ext();
    input.fields.list_table_fields = input.fields_ext->list_table_fields;
    input.fields.get_table_field = input.fields_ext->get_table_field;
    input.fields.add_table_field = input.fields_ext->add_table_field;
    return input;
}