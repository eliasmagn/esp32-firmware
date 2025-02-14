/* esp32-firmware
 * Copyright (C) 2020-2021 Erik Fleckstein <erik@tinkerforge.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "nfc.h"

#include "event_log_prefix.h"
#include "module_dependencies.h"
#include "bindings/errors.h"
#include "tools.h"
#include "nfc_bricklet_firmware_bin.embedded.h"

#if defined(BOARD_HAS_PSRAM)
#define MAX_AUTHORIZED_TAGS 32
#else
#define MAX_AUTHORIZED_TAGS 16
#endif

#define DETECTION_THRESHOLD_MS 2000

// Konstruktor: Wird hardwarebezogener Code nur auf WARP2/WARP3 initialisiert,
// ansonsten wird ein Dummy-Pfad gewählt.
NFC::NFC()
#if BUILD_IS_WARP2() || BUILD_IS_WARP3()
    : DeviceModule(nfc_bricklet_firmware_bin_data,
                   nfc_bricklet_firmware_bin_length,
                   "nfc",
                   "NFC",
                   "NFC",
                   [this](){ this->setup_nfc(); })
#else
    : DeviceModule(nullptr, 0, "nfc", "NFC", "NFC", [](){})
#endif
{
}

void NFC::pre_setup()
{
    this->DeviceModule::pre_setup();

    seen_tags_prototype = Config::Object({
        {"tag_type", Config::Uint8(0)},
        {"tag_id", Config::Str("", 0, NFC_TAG_ID_STRING_LENGTH)},
        {"last_seen", Config::Uint32(0)}
    });

    seen_tags = Config::Array(
        {},
        &seen_tags_prototype,
        0, TAG_LIST_LENGTH,
        Config::type_id<Config::ConfObject>()
    );

    config_authorized_tags_prototype = Config::Object({
        {"user_id", Config::Uint8(0)},
        {"tag_type", Config::Uint(0, 0, 5)},
        {"tag_id", Config::Str("", 0, NFC_TAG_ID_STRING_LENGTH)}
    });

    config = ConfigRoot{Config::Object({
        {"authorized_tags", Config::Array(
            {},
            &config_authorized_tags_prototype,
            0, MAX_AUTHORIZED_TAGS,
            Config::type_id<Config::ConfObject>())
        },
        {"deadtime_post_start", Config::Uint32(30)}
    }), [this](Config &cfg, ConfigSource source) -> String {
        Config *tags = (Config *)cfg.get("authorized_tags");

        // Prüfe Tag-ID-Format
        for (size_t tag = 0; tag < tags->count(); ++tag) {
            String id_copy = tags->get(tag)->get("tag_id")->asString();
            id_copy.toUpperCase();
            tags->get(tag)->get("tag_id")->updateString(id_copy);

            if (id_copy.length() != 0 && id_copy.length() % 3 != 2)
                return "Tag ID hat unerwartete Länge. Erwartetes Format: Hex-Bytes, getrennt durch Doppelpunkte (z.B. \"01:23:ab:3d\").";

            for(int i = 0; i < id_copy.length(); ++i) {
                char c = id_copy.charAt(i);
                if ((i % 3 != 2) && ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                    continue;
                if (i % 3 == 2 && c == ':')
                    continue;
                return "Tag ID enthält unerwartetes Zeichen. Erwartetes Format: Hex-Bytes, getrennt durch Doppelpunkte (z.B. \"01:23:ab:3d\").";
            }
        }

        if (source == ConfigSource::File) {
            // Alte Configs werden automatisch korrigiert
            bool update_file = false;
            for (size_t tag = 0; tag < tags->count(); ++tag) {
                uint8_t user_id = tags->get(tag)->get("user_id")->asUint();
                if (!users.is_user_configured(user_id)) {
                    logger.printfln("Korrigiere NFC Tag %s, der einen gelöschten User referenziert.", tags->get(tag)->get("tag_id")->asEphemeralCStr());
                    tags->get(tag)->get("user_id")->updateUint(0);
                    update_file = true;
                }
            }
            if (update_file)
                API::writeConfig("nfc/config", &cfg);

        } else {
            for (size_t tag = 0; tag < tags->count(); ++tag) {
                uint8_t user_id = tags->get(tag)->get("user_id")->asUint();
                if (!users.is_user_configured(user_id))
                    return String("Unbekannter User mit ID ") + (int)user_id + ".";
            }
        }

        return "";
    }};

    inject_tag = ConfigRoot{Config::Object({
        {"tag_type", Config::Uint(0, 0, 5)},
        {"tag_id", Config::Str("", 0, NFC_TAG_ID_STRING_LENGTH)}
    }), [this](Config &cfg, ConfigSource source) -> String {
        String id_copy = cfg.get("tag_id")->asString();
        id_copy.toUpperCase();
        cfg.get("tag_id")->updateString(id_copy);

        if (id_copy.length() != 0 && id_copy.length() % 3 != 2)
            return "Tag ID hat unerwartete Länge. Erwartetes Format: Hex-Bytes, getrennt durch Doppelpunkte (z.B. \"01:23:ab:3d\").";

        for(int i = 0; i < id_copy.length(); ++i) {
            char c = id_copy.charAt(i);
            if ((i % 3 != 2) && ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
                continue;
            if (i % 3 == 2 && c == ':')
                continue;
            return "Tag ID enthält unerwartetes Zeichen. Erwartetes Format: Hex-Bytes, getrennt durch Doppelpunkte (z.B. \"01:23:ab:3d\").";
        }

        return "";
    }};

#if MODULE_AUTOMATION_AVAILABLE()
    automation.register_trigger(
        AutomationTriggerID::NFC,
        Config::Object({
            {"tag_type", Config::Uint(0, 0, 5)},
            {"tag_id", Config::Str("", 0, NFC_TAG_ID_STRING_LENGTH)}
        }),
        nullptr,
        false
    );

    automation.register_action(
        AutomationActionID::NFCInjectTag,
        Config::Object({
            {"tag_type", Config::Uint(0, 0, 5)},
            {"tag_id", Config::Str("", 0, NFC_TAG_ID_STRING_LENGTH)},
            {"action", Config::Uint(0, 0, 2)}
        }),
        [this](const Config *config) {
            inject_tag.get("tag_type")->updateUint(config->get("tag_type")->asUint());
            inject_tag.get("tag_id")->updateString(config->get("tag_id")->asString());
            last_tag_injection = millis();
            tag_injection_action = config->get("action")->asUint();
            if (last_tag_injection == 0)
                last_tag_injection -= 1;
        },
        nullptr,
        false
    );
#endif

    auth_info = Config::Object({
        {"tag_type", Config::Uint8(0)},
        {"tag_id", Config::Str("", 0, NFC_TAG_ID_STRING_LENGTH)}
    });
}

//
// Hardware-spezifische Initialisierung – nur aktiv, wenn wir auf WARP2 oder WARP3 bauen.
// Ansonsten wird ein Dummy-Pfad gewählt, der lediglich die nötigen Datenstrukturen anlegt.
//
void NFC::setup_nfc()
{
#if BUILD_IS_WARP2() || BUILD_IS_WARP3()
    if (!this->DeviceModule::setup_device()) {
        return;
    }

    int result = tf_nfc_set_mode(&device, TF_NFC_MODE_SIMPLE);
    if (result != TF_E_OK) {
        if (!is_in_bootloader(result)) {
            logger.printfln("NFC set mode fehlgeschlagen (rc %d). NFC-Unterstützung wird deaktiviert.", result);
        }
        return;
    }

    // Leere Tag-Liste
    result = tf_nfc_simple_get_tag_id(&device, 255, nullptr, nullptr, nullptr, nullptr);
    if (result != TF_E_OK) {
        if (!is_in_bootloader(result)) {
            logger.printfln("Löschen der NFC Tag-Liste fehlgeschlagen (rc %d). NFC-Unterstützung wird deaktiviert.", result);
        }
        return;
    }

    initialized = true;
    api.addFeature("nfc");

    old_tags = static_cast<decltype(old_tags)>(calloc_dram(TAG_LIST_LENGTH, sizeof(*old_tags)));
    new_tags = static_cast<decltype(old_tags)>(calloc_dram(TAG_LIST_LENGTH, sizeof(*new_tags)));

#if MODULE_AUTOMATION_AVAILABLE()
    automation.set_enabled(AutomationTriggerID::NFC, true);
    automation.set_enabled(AutomationActionID::NFCInjectTag, true);
#endif
#else
    // Simuliere NFC: Erzeuge leere Tag-Listen, damit injected Tags verarbeitet werden können
    initialized = true;
    api.addFeature("nfc");
    old_tags = new tag_info_t[TAG_LIST_LENGTH];
    new_tags = new tag_info_t[TAG_LIST_LENGTH];
    memset(old_tags, 0, sizeof(tag_info_t) * TAG_LIST_LENGTH);
    memset(new_tags, 0, sizeof(tag_info_t) * TAG_LIST_LENGTH);
#endif
}

//
// Hardwarebezogene Statusprüfung – nur aktiv bei WARP2/WARP3.
//
void NFC::check_nfc_state()
{
#if BUILD_IS_WARP2() || BUILD_IS_WARP3()
    uint8_t mode = 0;
    int result = tf_nfc_get_mode(&device, &mode);
    if (result != TF_E_OK) {
        if (!is_in_bootloader(result)) {
            logger.printfln("Abfrage des NFC-Modus fehlgeschlagen, rc: %d", result);
        }
        return;
    }
    if (mode != TF_NFC_MODE_SIMPLE) {
        logger.printfln("NFC-Modus ungültig. Möglicherweise hat das Bricklet einen Reset durchgeführt?");
        setup_nfc();
    }
#endif
}

uint8_t NFC::get_user_id(tag_info_t *tag, uint8_t *tag_idx)
{
    for (uint8_t i = 0; i < auth_tag_count; ++i) {
        const auto &auth_tag = auth_tags[i];

        if (auth_tag.tag_type == tag->tag_type &&
            strncmp(auth_tag.tag_id, tag->tag_id, sizeof(auth_tag.tag_id)) == 0) {
            *tag_idx = i;
            return auth_tag.user_id;
        }
    }
    return 0;
}

void NFC::remove_user(uint8_t user_id)
{
    Config *tags = (Config *)config.get("authorized_tags");

    for (size_t i = 0; i < tags->count(); ++i) {
        if (tags->get(i)->get("user_id")->asUint() == user_id)
            tags->get(i)->get("user_id")->updateUint(0);
    }
    API::writeConfig("nfc/config", &config);
}

void NFC::tag_seen(tag_info_t *tag, bool injected)
{
    uint8_t idx = 0;
    uint8_t user_id = get_user_id(tag, &idx);

    if (user_id != 0) {
        bool blink_handled = false;
#if MODULE_OCPP_AVAILABLE()
        blink_handled = ocpp.on_tag_seen(tag->tag_id);
#endif
#if MODULE_EVSE_LED_AVAILABLE()
        if (!blink_handled)
            evse_led.set_module(EvseLed::Blink::Ack, 2000);
#endif

        auth_info.get("tag_type")->updateUint(tag->tag_type);
        auth_info.get("tag_id")->updateString(tag->tag_id);

        users.trigger_charge_action(user_id, injected ? USERS_AUTH_TYPE_NFC_INJECTION : USERS_AUTH_TYPE_NFC,
                                      auth_info.value,
                                      injected ? tag_injection_action : TRIGGER_CHARGE_ANY,
                                      3_s, deadtime_post_start);
    } else {
        bool blink_handled = false;
#if MODULE_OCPP_AVAILABLE()
        blink_handled = ocpp.on_tag_seen(tag->tag_id);
#endif
#if MODULE_EVSE_LED_AVAILABLE()
        if (!blink_handled)
            evse_led.set_module(EvseLed::Blink::Nack, 2000);
#endif
    }

#if MODULE_AUTOMATION_AVAILABLE()
    automation.trigger(AutomationTriggerID::NFC, tag, this);
#endif
}

const char *lookup = "0123456789ABCDEF";

// Hilfsfunktion: Wandelt Byte-Array in einen Hex-String (mit Doppelpunkten) um.
void tag_id_bytes_to_string(const uint8_t *tag_id, uint8_t tag_id_len, char buf[NFC_TAG_ID_STRING_LENGTH + 1])
{
    for (int i = 0; i < tag_id_len; ++i) {
        uint8_t b = tag_id[i];
        uint8_t hi = (b & 0xF0) >> 4;
        uint8_t lo = b & 0x0F;
        buf[3 * i] = lookup[hi];
        buf[3 * i + 1] = lookup[lo];
        buf[3 * i + 2] = ':';
    }
    if (tag_id_len == 0)
        buf[0] = '\0';
    else
        buf[3 * tag_id_len - 1] = '\0';
}

//
// update_seen_tags() – Liest die aktuell sichtbaren Tags ein.
// Der hardwarebezogene Teil (Über das Bricklet) wird nur bei WARP2/WARP3 genutzt;
// ansonsten wird angenommen, dass keine Tag-Erfassung stattfindet (außer evtl. injected tags).
//
/* void NFC::update_seen_tags()
{
#if BUILD_IS_WARP2() || BUILD_IS_WARP3()
    for (int i = 0; i < TAG_LIST_LENGTH - 1; ++i) {
        uint8_t tag_id_bytes[10];
        uint8_t tag_id_len = 0;
        int result = tf_nfc_simple_get_tag_id(&device, i, &new_tags[i].tag_type, tag_id_bytes, &tag_id_len, &new_tags[i].last_seen);
        if (result != TF_E_OK) {
            if (!is_in_bootloader(result)) {
                logger.printfln("Abfrage von Tag-ID %d fehlgeschlagen, rc: %d", i, result);
            }
            continue;
        }
        tag_id_bytes_to_string(tag_id_bytes, tag_id_len, new_tags[i].tag_id);
    }
#else
    // Ohne NFC-Hardware: Setze alle nicht-injected Tags auf "nicht gesehen"
    for (int i = 0; i < TAG_LIST_LENGTH - 1; ++i) {
        new_tags[i].tag_type = 0;
        new_tags[i].tag_id[0] = '\0';
        new_tags[i].last_seen = 0;
    }
#endif

    // Unabhängig von der Hardware: Behandlung von injected tags (immer aktiv)
    if (last_tag_injection == 0 || deadline_elapsed(last_tag_injection + 1000 * 60 * 60 * 24)) {
        last_tag_injection = 0;
        new_tags[TAG_LIST_LENGTH - 1].tag_type = 0;
        new_tags[TAG_LIST_LENGTH - 1].tag_id[0] = '\0';
        new_tags[TAG_LIST_LENGTH - 1].last_seen = 0;
    } else {
        new_tags[TAG_LIST_LENGTH - 1].tag_type = inject_tag.get("tag_type")->asUint();
        strncpy(new_tags[TAG_LIST_LENGTH - 1].tag_id, inject_tag.get("tag_id")->asEphemeralCStr(), sizeof(new_tags[TAG_LIST_LENGTH - 1].tag_id));
        new_tags[TAG_LIST_LENGTH - 1].last_seen = millis() - last_tag_injection;
    }

    // Aktualisiere den Config-Zustand
    for (size_t i = 0; i < TAG_LIST_LENGTH; ++i) {
        Config *seen_tag_state = static_cast<Config *>(seen_tags.get(i));
        tag_info_t *new_tag = new_tags + i;
        seen_tag_state->get("last_seen")->updateUint(new_tag->last_seen);
        seen_tag_state->get("tag_type")->updateUint(new_tag->tag_type);
        seen_tag_state->get("tag_id")->updateString(new_tag->tag_id);
    }

    // Vergleiche alte und neue Tag-Liste, um "neue" Ereignisse zu erkennen
    for (int new_idx = 0; new_idx < TAG_LIST_LENGTH; ++new_idx) {
        if (new_tags[new_idx].last_seen == 0)
            continue;

        int min_old_idx = -1;
        for (int old_idx = 0; old_idx < TAG_LIST_LENGTH; ++old_idx) {
            if (old_tags[old_idx].last_seen == 0)
                continue;
            if(strncmp(old_tags[old_idx].tag_id, new_tags[new_idx].tag_id, NFC_TAG_ID_STRING_LENGTH) != 0)
                continue;
            if (min_old_idx == -1 || old_tags[min_old_idx].last_seen > old_tags[old_idx].last_seen)
                min_old_idx = old_idx;
        }
        if (min_old_idx == -1) {
            tag_seen(&new_tags[new_idx], new_idx == TAG_LIST_LENGTH - 1);
            continue;
        }
        bool old_seen = old_tags[min_old_idx].last_seen < DETECTION_THRESHOLD_MS;
        bool new_seen = new_tags[new_idx].last_seen < DETECTION_THRESHOLD_MS;
        if (!old_seen && new_seen) {
            tag_seen(&new_tags[new_idx], new_idx == TAG_LIST_LENGTH - 1);
            continue;
        }
    }

    // Tausche alte und neue Listen (Pointer-Tausch)
    tag_info_t *tmp = old_tags;
    old_tags = new_tags;
    new_tags = tmp;
} */


void NFC::update_seen_tags()
{
#if BUILD_IS_WARP2() || BUILD_IS_WARP3()
    for (int i = 0; i < TAG_LIST_LENGTH - 1; ++i) {
        uint8_t tag_id_bytes[10];
        uint8_t tag_id_len = 0;
        int result = tf_nfc_simple_get_tag_id(&device, i, &new_tags[i].tag_type, tag_id_bytes, &tag_id_len, &new_tags[i].last_seen);
        if (result != TF_E_OK) {
            if (!is_in_bootloader(result)) {
                logger.printfln("[NFC] Abfrage von Tag-ID %d fehlgeschlagen, rc: %d", i, result);
            }
            continue;
        }
        tag_id_bytes_to_string(tag_id_bytes, tag_id_len, new_tags[i].tag_id);
        logger.printfln("[NFC] Hardware-Tag[%d]: %s, type: %u, last_seen: %u", i, new_tags[i].tag_id, new_tags[i].tag_type, new_tags[i].last_seen);
    }
#else
    // Ohne NFC-Hardware: Setze alle nicht-injected Tags auf "nicht gesehen"
    for (int i = 0; i < TAG_LIST_LENGTH - 1; ++i) {
        new_tags[i].tag_type = 0;
        new_tags[i].tag_id[0] = '\0';
        new_tags[i].last_seen = 0;
    }
    logger.printfln("[NFC] Kein NFC-Hardware vorhanden. Alle Hardware-Tags als 'nicht gesehen' markiert.");
#endif

    // Bearbeite den injizierten Tag (immer im letzten Slot)
    if (last_tag_injection == 0 || deadline_elapsed(last_tag_injection + 1000 * 60 * 60 * 24)) {
        last_tag_injection = 0;
        new_tags[TAG_LIST_LENGTH - 1].tag_type = 0;
        new_tags[TAG_LIST_LENGTH - 1].tag_id[0] = '\0';
        new_tags[TAG_LIST_LENGTH - 1].last_seen = 0;
        logger.printfln("[NFC] Injizierter Tag gelöscht, da last_tag_injection abgelaufen.");
    } else {
        new_tags[TAG_LIST_LENGTH - 1].tag_type = inject_tag.get("tag_type")->asUint();
        strncpy(new_tags[TAG_LIST_LENGTH - 1].tag_id, inject_tag.get("tag_id")->asEphemeralCStr(), sizeof(new_tags[TAG_LIST_LENGTH - 1].tag_id));
        new_tags[TAG_LIST_LENGTH - 1].last_seen = millis() - last_tag_injection;
        logger.printfln("[NFC] Injizierter Tag gesetzt: %s, type: %u, last_seen: %u", 
                         new_tags[TAG_LIST_LENGTH - 1].tag_id, 
                         new_tags[TAG_LIST_LENGTH - 1].tag_type, 
                         new_tags[TAG_LIST_LENGTH - 1].last_seen);
    }

    // Aktualisiere den Config-Zustand
    for (size_t i = 0; i < TAG_LIST_LENGTH; ++i) {
        Config *seen_tag_state = static_cast<Config *>(seen_tags.get(i));
        tag_info_t *new_tag = new_tags + i;
        seen_tag_state->get("last_seen")->updateUint(new_tag->last_seen);
        seen_tag_state->get("tag_type")->updateUint(new_tag->tag_type);
        seen_tag_state->get("tag_id")->updateString(new_tag->tag_id);
    }

    // Vergleiche neue Liste mit alter Liste
    for (int new_idx = 0; new_idx < TAG_LIST_LENGTH; ++new_idx) {
        if (new_tags[new_idx].last_seen == 0)
            continue;

        int min_old_idx = -1;
        for (int old_idx = 0; old_idx < TAG_LIST_LENGTH; ++old_idx) {
            if (old_tags[old_idx].last_seen == 0)
                continue;
            if(strncmp(old_tags[old_idx].tag_id, new_tags[new_idx].tag_id, NFC_TAG_ID_STRING_LENGTH) != 0)
                continue;
            if (min_old_idx == -1 || old_tags[min_old_idx].last_seen > old_tags[old_idx].last_seen)
                min_old_idx = old_idx;
        }
        if (min_old_idx == -1) {
            logger.printfln("[NFC] Neuer Tag erkannt an Index %d: %s", new_idx, new_tags[new_idx].tag_id);
            tag_seen(&new_tags[new_idx], new_idx == TAG_LIST_LENGTH - 1);
            continue;
        }
        bool old_seen = old_tags[min_old_idx].last_seen < DETECTION_THRESHOLD_MS;
        bool new_seen = new_tags[new_idx].last_seen < DETECTION_THRESHOLD_MS;
        if (!old_seen && new_seen) {
            logger.printfln("[NFC] Tag wurde erneut als neu erkannt an Index %d: %s", new_idx, new_tags[new_idx].tag_id);
            tag_seen(&new_tags[new_idx], new_idx == TAG_LIST_LENGTH - 1);
            continue;
        }
    }

    // Tausche alte und neue Listen (Pointertausch)
    tag_info_t *tmp = old_tags;
    old_tags = new_tags;
    new_tags = tmp;
    logger.printfln("[NFC] update_seen_tags abgeschlossen. Pointertausch durchgeführt.");
}


void NFC::setup_auth_tags()
{
    const auto *auth_tags_cfg = (Config *)config.get("authorized_tags");
    auth_tag_count = auth_tags_cfg->count();
    if (auth_tag_count == 0)
        return;

    auth_tags = heap_alloc_array<auth_tag_t>(auth_tag_count);
    memset(auth_tags.get(), 0, sizeof(auth_tag_t) * auth_tag_count);

    for (size_t i = 0; i < auth_tag_count; ++i) {
        const auto tag = auth_tags_cfg->get(i);
        auth_tags[i].tag_type = tag->get("tag_type")->asUint();
        auth_tags[i].user_id = tag->get("user_id")->asUint();
        tag->get("tag_id")->asString().toCharArray(auth_tags[i].tag_id, sizeof(auth_tags[i].tag_id));
    }

    this->deadtime_post_start = seconds_t{config.get("deadtime_post_start")->asUint()};
}

// void NFC::setup()
// {
//     setup_nfc();
//     if (!device_found)
//         return;

//     api.restorePersistentConfig("nfc/config", &config);
//     setup_auth_tags();

//     for (int i = 0; i < TAG_LIST_LENGTH; ++i) {
//         seen_tags.add();
//     }

//     task_scheduler.scheduleWithFixedDelay([this]() {
//         this->check_nfc_state();
//     }, 5_m, 5_m);

//     task_scheduler.scheduleWithFixedDelay([this]() {
//         this->update_seen_tags();
//     }, 300_ms);
// }


void NFC::setup()
{
    setup_nfc();


    api.restorePersistentConfig("nfc/config", &config);
    setup_auth_tags();

    for (int i = 0; i < TAG_LIST_LENGTH; ++i) {
        seen_tags.add();
    }
    if (device_found){
       task_scheduler.scheduleWithFixedDelay([this]() {
         this->check_nfc_state();
       }, 5_m, 5_m);

       task_scheduler.scheduleWithFixedDelay([this]() {
          this->update_seen_tags();
       }, 300_ms);
    }
}


//  void NFC::register_urls()
// {
//     api.addState("nfc/seen_tags", &seen_tags, {}, {"tag_id", "tag_type"});
//     api.addPersistentConfig("nfc/config", &config, {}, {"tag_id", "tag_type"});
//     api.addCommand("nfc/inject_tag", &inject_tag, {"tag_id", "tag_type"}, [this](String &/*errmsg*/) {
//         last_tag_injection = millis();
//         tag_injection_action = TRIGGER_CHARGE_ANY;
//         logger.printfln("inject tag:");

//         if (last_tag_injection == 0)
//             last_tag_injection -= 1;
//     }, true);

//     api.addCommand("nfc/inject_tag_start", &inject_tag, {"tag_id", "tag_type"}, [this](String &/*errmsg*/) {
//         last_tag_injection = millis();
//         tag_injection_action = TRIGGER_CHARGE_START;
//         if (last_tag_injection == 0)
//             last_tag_injection -= 1;
//     }, true);

//     api.addCommand("nfc/inject_tag_stop", &inject_tag, {"tag_id", "tag_type"}, [this](String &/*errmsg*/) {
//         last_tag_injection = millis();
//         tag_injection_action = TRIGGER_CHARGE_STOP;
//         if (last_tag_injection == 0)
//             last_tag_injection -= 1;
//     }, true);

//     this->DeviceModule::register_urls();
// }
 

void NFC::register_urls()
{
    api.addState("nfc/seen_tags", &seen_tags, {}, {"tag_id", "tag_type"});
    api.addPersistentConfig("nfc/config", &config, {}, {"tag_id", "tag_type"});
    
    // Injection per API: Standard Injection
    api.addCommand("nfc/inject_tag", &inject_tag, {"tag_id", "tag_type"}, [this](String &/*errmsg*/) {
        last_tag_injection = millis();
        tag_injection_action = TRIGGER_CHARGE_ANY;
        logger.printfln("[NFC] inject_tag called: tag_id = %s, tag_type = %u, last_tag_injection = %u", 
                          inject_tag.get("tag_id")->asEphemeralCStr(), 
                          inject_tag.get("tag_type")->asUint(), last_tag_injection);
        // Falls last_tag_injection == 0, reduziere um 1
        if (last_tag_injection == 0) {
            last_tag_injection -= 1;
        }
        #if !(BUILD_IS_WARP2() || BUILD_IS_WARP3())
        update_seen_tags();
        #endif
    }, true);

    // Injection: Start
    api.addCommand("nfc/inject_tag_start", &inject_tag, {"tag_id", "tag_type"}, [this](String &/*errmsg*/) {
        last_tag_injection = millis();
        tag_injection_action = TRIGGER_CHARGE_START;
        logger.printfln("[NFC] inject_tag_start called: tag_id = %s, tag_type = %u, last_tag_injection = %u", 
                          inject_tag.get("tag_id")->asEphemeralCStr(), 
                          inject_tag.get("tag_type")->asUint(), last_tag_injection);
        if (last_tag_injection == 0){
            last_tag_injection -= 1;
        }
        #if !(BUILD_IS_WARP2() || BUILD_IS_WARP3())
        update_seen_tags();
        #endif
    }, true);

    // Injection: Stop
    api.addCommand("nfc/inject_tag_stop", &inject_tag, {"tag_id", "tag_type"}, [this](String &/*errmsg*/) {
        last_tag_injection = millis();
        tag_injection_action = TRIGGER_CHARGE_STOP;
        logger.printfln("[NFC] inject_tag_stop called: tag_id = %s, tag_type = %u, last_tag_injection = %u", 
                          inject_tag.get("tag_id")->asEphemeralCStr(), 
                          inject_tag.get("tag_type")->asUint(), last_tag_injection);
        if (last_tag_injection == 0){
            last_tag_injection -= 1;
        }
        #if !(BUILD_IS_WARP2() || BUILD_IS_WARP3())
        update_seen_tags();
        #endif
    }, true);

    this->DeviceModule::register_urls();
}


void NFC::loop()
{
    this->DeviceModule::loop();
}

#if MODULE_AUTOMATION_AVAILABLE()
bool NFC::has_triggered(const Config *conf, void *data)
{
    const Config *cfg = static_cast<const Config *>(conf->get());
    tag_info_t *tag = (tag_info_t *)data;
    switch (conf->getTag<AutomationTriggerID>()) {
        case AutomationTriggerID::NFC:
            if (cfg->get("tag_type")->asUint() == tag->tag_type && cfg->get("tag_id")->asString() == tag->tag_id) {
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}
#endif
