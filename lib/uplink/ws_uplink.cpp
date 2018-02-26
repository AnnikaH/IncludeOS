// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2017 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ws_uplink.hpp"
#include "common.hpp"

#ifndef RAPIDJSON_HAS_STDSTRING
  #define RAPIDJSON_HAS_STDSTRING 1
#endif

#ifndef RAPIDJSON_THROWPARSEEXCEPTION
  #define RAPIDJSON_THROWPARSEEXCEPTION 1
#endif

#include <rapidjson/document.h>
#include <rapidjson/writer.h>

#include <os>
#include <util/sha1.hpp>
#include <kernel/pci_manager.hpp>
#include <hw/pci_device.hpp>
#include <kernel/cpuid.hpp>
#include <statman>
#include <config>
#include "log.hpp"

#include <debug_mothership_team>
#ifdef DEBUG_MOTHERSHIP_TEAM
#define debugM(fmt, ...) debugMothership("Uplink", fmt, ##__VA_ARGS__)
#else
#define debugM(fmt, ...)
#endif

namespace uplink {
  constexpr std::chrono::seconds WS_uplink::heartbeat_interval;

  WS_uplink::WS_uplink(Config config)
    : config_{std::move(config)},
      inet_{*config_.inet},
      id_{inet_.link_addr().to_string()},
      parser_({this, &WS_uplink::handle_transport}),
      heartbeat_timer({this, &WS_uplink::on_heartbeat_timer})
  {
    if(liu::LiveUpdate::is_resumable() && OS::is_live_updated())
    {
      MYINFO("Found resumable state, try restoring...\n");
      liu::LiveUpdate::resume("uplink", {this, &WS_uplink::restore});

      if(liu::LiveUpdate::partition_exists("conntrack"))
        liu::LiveUpdate::resume("conntrack", {this, &WS_uplink::restore_conntrack});
    }

    Log::get().set_flush_handler({this, &WS_uplink::send_log});

    liu::LiveUpdate::register_partition("uplink", {this, &WS_uplink::store});

    CHECK(config_.reboot, "Reboot on panic");

    CHECK(config_.serialize_ct, "Serialize Conntrack");
    if(config_.serialize_ct)
      liu::LiveUpdate::register_partition("conntrack", {this, &WS_uplink::store_conntrack});

    if(inet_.is_configured())
    {
      start(inet_);
    }
    // if not, register on config event
    else
    {
      MYINFO("Interface %s not yet configured, starts when ready.\n", inet_.ifname().c_str());
      inet_.on_config({this, &WS_uplink::start});
    }
  }

  void WS_uplink::start(net::Inet<net::IP4>& inet) {
    MYINFO("Starting WS uplink on %s with ID %s\n",
      inet.ifname().c_str(), id_.c_str());

    Expects(inet.ip_addr() != 0 && "Network interface not configured");
    Expects(not config_.url.empty());

    client_ = std::make_unique<http::Client>(inet.tcp(),
      http::Client::Request_handler{this, &WS_uplink::inject_token});

    debugM("HTTP client created - now calling auth\n");

    auth();
  }

  void WS_uplink::store(liu::Storage& store, const liu::buffer_t*)
  {
    debugM("WS_uplink::store\n");
    // BINARY HASH
    store.add_string(0, update_hash_);
    // nanos timestamp of when update begins
    store.add<uint64_t> (1, OS::nanos_since_boot());
  }

  void WS_uplink::restore(liu::Restore& store)
  {
    debugM("WS_uplink::restore\n");

    // BINARY HASH
    binary_hash_ = store.as_string(); store.go_next();

    // calculate update cycles taken
    uint64_t prev_nanos = store.as_type<uint64_t> (); store.go_next();
    this->update_time_taken = OS::nanos_since_boot() - prev_nanos;

    INFO2("Update took %.3f millis", this->update_time_taken / 1.0e6);
  }

  std::string WS_uplink::auth_data() const
  {
    return "{ \"id\": \"" + id_ + "\", \"key\": \"" + config_.token + "\"}";
  }

  void WS_uplink::auth()
  {
    std::string url{"http://"};
    url.append(config_.url).append("/auth");

    //static const std::string auth_data{"{ \"id\": \"testor\", \"key\": \"kappa123\"}"};

    MYINFO("Sending auth request to %s\n", url.c_str());

    client_->post(http::URI{url},
      { {"Content-Type", "application/json"} },
      auth_data(),
      {this, &WS_uplink::handle_auth_response},
      http::Client::Options{15s});
  }

  void WS_uplink::handle_auth_response(http::Error err, http::Response_ptr res, http::Connection&)
  {
    debugM("WS_uplink::handle_auth_response\n");

    if(err)
    {
      MYINFO("Auth failed - %s\n", err.to_string().c_str());
      retry_auth();
      return;
    }

    if(res->status_code() != http::OK)
    {
      MYINFO("Auth failed - %s\n", res->to_string().c_str());
      retry_auth();
      return;
    }

    retry_backoff = 0;

    MYINFO("Auth success (token received)");
    token_ = std::string(res->body());

    debugM("Ready to dock\n");

    dock();
  }

  void WS_uplink::retry_auth()
  {
    debugM("WS_uplink::retry_auth\n");

    if(retry_backoff < 6)
      ++retry_backoff;

    std::chrono::seconds secs{5 * retry_backoff};

    MYINFO("Retry auth in %lld seconds...\n", secs.count());
    retry_timer.restart(secs, {this, &WS_uplink::auth});
  }

  void WS_uplink::dock()
  {
    debugM("WS_uplink::dock\n");

    Expects(not token_.empty() and client_ != nullptr);

    std::string url{"ws://"};
    url.append(config_.url).append("/dock");

    MYINFO("Dock attempt to %s\n", url.c_str());

    debugM("Ready to connect\n");

    net::WebSocket::connect(*client_, http::URI{url}, {this, &WS_uplink::establish_ws});
  }

  void WS_uplink::establish_ws(net::WebSocket_ptr ws)
  {
    debugM("WS_uplink::establish_ws\n");

    if(ws == nullptr) {
      MYINFO("Failed to establish websocket\n");
      retry_auth();
      return;
    }

    debugM("Websocket != nullptr\n");

    ws_ = std::move(ws);
    ws_->on_read = {this, &WS_uplink::parse_transport};
    ws_->on_error = [](const auto& reason) {
      MYINFO("(WS err) %s\n", reason.c_str());
    };

    ws_->on_close = {this, &WS_uplink::handle_ws_close};

    flush_log();

    debugM("Websocket established\n");

    send_ident();

    send_uplink();

    ws_->on_ping = {this, &WS_uplink::handle_ping};
    ws_->on_pong_timeout = {this, &WS_uplink::handle_pong_timeout};

    heart_retries_left = heartbeat_retries;
    last_ping = RTC::now();
    heartbeat_timer.start(std::chrono::seconds(10));

    debugM("Heartbeat timer started\n");
  }

  void WS_uplink::handle_ws_close(uint16_t code)
  {
    debugM("WS_uplink::handle_ws_close\n");
    (void) code;
    auth();
  }

  bool WS_uplink::handle_ping(const char*, size_t)
  {
    debugM("WS_uplink::handle_ping\n");
    last_ping = RTC::now();
    return true;
  }

  void WS_uplink::handle_pong_timeout(net::WebSocket&)
  {
    debugM("WS_uplink::handle_pong_timeout\n");
    heart_retries_left--;
    MYINFO("! Pong timeout. Retries left %i\n", heart_retries_left);
  }

  void WS_uplink::on_heartbeat_timer()
  {
    debugM("WS_uplink::on_heartbeat_timer\n");

    if (not is_online()) {
      MYINFO("Can't heartbeat on closed conection.\n");
      return;
    }

    debugM("Is online\n");

    if(missing_heartbeat())
    {
      if (not heart_retries_left)
      {
        MYINFO("No reply after %i pings. Reauth.\n", heartbeat_retries);
        ws_->close();
        auth();
        return;
      }

      auto ping_ok = ws_->ping(std::chrono::seconds(5));

      if (not ping_ok)
      {
        MYINFO("Heartbeat pinging failed. Reauth.\n");
        auth();
        return;
      }

      debugM("Heartbeat pinging ok\n");
    }

    debugM("Starting heartbeat timer\n");

    heartbeat_timer.start(std::chrono::seconds(10));
  }

  void WS_uplink::parse_transport(net::WebSocket::Message_ptr msg)
  {
    debugM("WS_uplink::parse_transport\n");

    if(msg != nullptr) {
      debugM("msg is not nullptr - parsing\n");
      parser_.parse(msg->data(), msg->size());
    }
    else {
      MYINFO("Malformed WS message, try to re-establish\n");
      send_error("WebSocket error");
      ws_->close();
      ws_ = nullptr;
      dock();
    }
  }

  void WS_uplink::handle_transport(Transport_ptr t)
  {
    debugM("WS_uplink::handle_transport\n");

    if(UNLIKELY(t == nullptr))
    {
      MYINFO("Something went terribly wrong...\n");
      return;
    }

    debugM("t != nullptr\n");

    debugM("New transport (%lu bytes)\n", t->size());

    switch(t->code())
    {
      case Transport_code::UPDATE:
      {
        MYINFO("Update received - commencing update...\n");

        update({t->begin(), t->end()});
        return;
      }

      case Transport_code::STATS:
      {
        debugM("Transport code == STATS\n");
        send_stats();
        break;
      }

      default:
      {
        debugM("Default transport code case\n");
        INFO2("Bad transport");
      }
    }
  }

  void WS_uplink::update(const std::vector<char>& buffer)
  {
    debugM("WS_uplink::update\n");

    static SHA1 checksum;
    checksum.update(buffer);
    update_hash_ = checksum.as_hex();

    debugM("Creating transport to tell that the update has been received\n");

    // send a reponse with the to tell we received the update
    auto trans = Transport{Header{Transport_code::UPDATE, static_cast<uint32_t>(update_hash_.size())}};
    trans.load_cargo(update_hash_.data(), update_hash_.size());
    ws_->write(trans.data().data(), trans.data().size());
    ws_->close();

    debugM("ws is now closed - starting update\n");

    // do the update
    Timers::oneshot(std::chrono::milliseconds(10),
    [this, copy = buffer] (int) {
      try {
        debugM("Trying to liveupdate: liu::LiveUpdate::exec\n");
        liu::LiveUpdate::exec(copy);
      }
      catch (std::exception& e) {
        debugM("Exception thrown in liu::LiveUpdate::exec\n");
        INFO2("LiveUpdate::exec() failed: %s\n", e.what());
        debugM("Restoring environment\n");
        liu::LiveUpdate::restore_environment();
        debugM("Establishing new connection - calling auth\n");
        // establish new connection
        this->auth();
      }
    });
  }

  template <typename Writer, typename Stack_ptr>
  void serialize_stack(Writer& writer, const Stack_ptr& stack)
  {
    debugM("serialize_stack\n");

    if(stack != nullptr)
    {
      debugM("stack != nullptr\n");

      writer.StartObject();

      writer.Key("name");
      writer.String(stack->ifname());

      writer.Key("addr");
      writer.String(stack->ip_addr().str());

      writer.Key("netmask");
      writer.String(stack->netmask().str());

      writer.Key("gateway");
      writer.String(stack->gateway().str());

      writer.Key("dns");
      writer.String(stack->dns_addr().str());

      writer.Key("mac");
      writer.String(stack->link_addr().to_string());

      writer.Key("driver");
      writer.String(stack->nic().driver_name());

      writer.EndObject();
    }
  }

  void WS_uplink::send_ident()
  {
    MYINFO("Sending ident\n");
    using namespace rapidjson;

    StringBuffer buf;

    Writer<StringBuffer> writer{buf};

    writer.StartObject();

    const auto& sysinfo = __arch_system_info();
    writer.Key("uuid");
    writer.String(sysinfo.uuid);

    writer.Key("version");
    writer.String(OS::version());

    writer.Key("service");
    writer.String(Service::name());

    if(not binary_hash_.empty())
    {
      writer.Key("binary");
      writer.String(binary_hash_);
    }

    if(update_time_taken > 0)
    {
      writer.Key("update_time_taken");
      writer.Uint64(update_time_taken);
    }

    writer.Key("arch");
    writer.String(OS::arch());

    writer.Key("physical_ram");
    writer.Uint64(sysinfo.physical_memory);

    // CPU Features
    auto features = CPUID::detect_features_str();
    writer.Key("cpu_features");
    writer.StartArray();
    for (auto f : features) {
      writer.String(f);
    }
    writer.EndArray();

    // PCI devices
    auto devices = PCI_manager::devices();
    writer.Key("devices");
    writer.StartArray();
    for (auto* dev : devices) {
      writer.String(dev->to_string());
    }
    writer.EndArray();

    // Network
    writer.Key("net");

    writer.StartArray();

    auto& stacks = net::Super_stack::inet().ip4_stacks();
    for(const auto& stack : stacks) {
      for(const auto& pair : stack)
        serialize_stack(writer, pair.second);
    }

    writer.EndArray();

    writer.EndObject();

    std::string str = buf.GetString();

    MYINFO("%s\n", str.c_str());

    send_message(Transport_code::IDENT, str.data(), str.size());
  }

  void WS_uplink::send_uplink() {
    MYINFO("Sending uplink\n");
    using namespace rapidjson;

    StringBuffer buf;
    Writer<StringBuffer> writer{buf};

    writer.StartObject();

    writer.Key("url");
    writer.String(config_.url);

    writer.Key("token");
    writer.String(config_.token);

    writer.Key("reboot");
    writer.Bool(config_.reboot);

    writer.EndObject();

    std::string str = buf.GetString();

    MYINFO("%s\n", str.c_str());

    auto transport = Transport{Header{Transport_code::UPLINK, static_cast<uint32_t>(str.size())}};
    transport.load_cargo(str.data(), str.size());
    ws_->write(transport.data().data(), transport.data().size());
  }

  void WS_uplink::send_message(Transport_code code, const char* data, size_t len) {
    debugM("WS_uplink::send_message\n");

    auto transport = Transport{Header{code, static_cast<uint32_t>(len)}};

    transport.load_cargo(data, len);

    ws_->write(transport.data().data(), transport.data().size());
  }

  void WS_uplink::send_error(const std::string& err)
  {
    debugM("WS_uplink::send_error\n");
    send_message(Transport_code::ERROR, err.c_str(), err.size());
  }

  void WS_uplink::send_log(const char* data, size_t len)
  {
    debugM("WS_uplink::send_log\n");
    if(not config_.ws_logging)
      return;

    if(is_online() and ws_->get_connection()->is_writable())
    {
      debugM("Is online and connection is writable - sending message\n");
      send_message(Transport_code::LOG, data, len);
    }
    else
    {
      debugM("Is offline or connection is not writable - adding data to log buffer\n");
      // buffer for later
      logbuf_.insert(logbuf_.end(), data, data+len);
    }
  }

  void WS_uplink::flush_log()
  {
    debugM("WS_uplink::flush_log\n");

    if(not logbuf_.empty())
    {
      debugM("Log buffer is not empty\n");
      if(config_.ws_logging)
      {
        debugM("Sending message\n");
        send_message(Transport_code::LOG, logbuf_.data(), logbuf_.size());
      }
      debugM("Clearing and shrinking buffer to fit\n");
      logbuf_.clear();
      logbuf_.shrink_to_fit();
    }
  }

  void WS_uplink::panic(const char* why){
    debugM("WS_uplink sending panic\n");
    Log::get().flush();
    send_message(Transport_code::PANIC, why, strlen(why));
    ws_->close();
    inet_.nic().flush();

    debugM("ws has been closed and nic has been flushed - rebooting if is true\n");

    if(config_.reboot) OS::reboot();
  }

  void WS_uplink::send_stats()
  {
    debugM("WS_uplink::send_stats\n");
    using namespace rapidjson;

    StringBuffer buf;
    Writer<StringBuffer> writer{buf};

    writer.StartArray();
    auto& statman = Statman::get();
    for(auto it = statman.begin(); it != statman.end(); ++it)
    {
      auto& stat = *it;
      writer.StartObject();

      writer.Key("name");
      writer.String(stat.name());

      writer.Key("value");
      switch(stat.type()) {
        case Stat::UINT64:  writer.Uint64(stat.get_uint64()); break;
        case Stat::UINT32:  writer.Uint(stat.get_uint32()); break;
        case Stat::FLOAT:   writer.Double(stat.get_float()); break;
      }

      writer.EndObject();
    }
    writer.EndArray();

    std::string str = buf.GetString();

    send_message(Transport_code::STATS, str.data(), str.size());
  }

  std::shared_ptr<net::Conntrack> get_first_conntrack()
  {
    debugM("get_first_conntrack\n");
    for(auto& stacks : net::Super_stack::inet().ip4_stacks()) {
      for(auto& stack : stacks)
      {
        if(stack.second != nullptr and stack.second->conntrack() != nullptr)
          return stack.second->conntrack();
      }
    }
    return nullptr;
  }

  void WS_uplink::store_conntrack(liu::Storage& store, const liu::buffer_t*)
  {
    debugM("WS_uplink::store_conntrack\n");
    // NOTE: Only support serializing one conntrack atm
    auto ct = get_first_conntrack();
    if(not ct)
      return;

    liu::buffer_t buf;
    ct->serialize_to(buf);
    store.add_buffer(0, buf);
  }

  void WS_uplink::restore_conntrack(liu::Restore& store)
  {
    debugM("WS_uplink::restore_conntrack\n");
    // NOTE: Only support deserializing one conntrack atm
    auto ct = get_first_conntrack();
    if(not ct)
      return;

    auto buf = store.as_buffer();
    ct->deserialize_from(buf.data());
  }

}
