/* ***********************************************************
 * This file was automatically generated on 2021-11-18.      *
 *                                                           *
 * C/C++ for Microcontrollers Bindings Version 2.0.0         *
 *                                                           *
 * If you have a bugfix for this file and want to commit it, *
 * please fix the bug in the generator. You can find a link  *
 * to the generators git repository on tinkerforge.com       *
 *************************************************************/


#include "bricklet_compass.h"
#include "base58.h"
#include "endian_convert.h"
#include "errors.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


#if TF_IMPLEMENT_CALLBACKS != 0
static bool tf_compass_callback_handler(void *dev, uint8_t fid, TF_PacketBuffer *payload) {
    TF_Compass *compass = (TF_Compass *) dev;
    (void)payload;

    switch (fid) {
        case TF_COMPASS_CALLBACK_HEADING: {
            TF_Compass_HeadingHandler fn = compass->heading_handler;
            void *user_data = compass->heading_user_data;
            if (fn == NULL) {
                return false;
            }

            int16_t heading = tf_packet_buffer_read_int16_t(payload);
            TF_HALCommon *hal_common = tf_hal_get_common((TF_HAL *)compass->tfp->hal);
            hal_common->locked = true;
            fn(compass, heading, user_data);
            hal_common->locked = false;
            break;
        }

        case TF_COMPASS_CALLBACK_MAGNETIC_FLUX_DENSITY: {
            TF_Compass_MagneticFluxDensityHandler fn = compass->magnetic_flux_density_handler;
            void *user_data = compass->magnetic_flux_density_user_data;
            if (fn == NULL) {
                return false;
            }

            int32_t x = tf_packet_buffer_read_int32_t(payload);
            int32_t y = tf_packet_buffer_read_int32_t(payload);
            int32_t z = tf_packet_buffer_read_int32_t(payload);
            TF_HALCommon *hal_common = tf_hal_get_common((TF_HAL *)compass->tfp->hal);
            hal_common->locked = true;
            fn(compass, x, y, z, user_data);
            hal_common->locked = false;
            break;
        }

        default:
            return false;
    }

    return true;
}
#else
static bool tf_compass_callback_handler(void *dev, uint8_t fid, TF_PacketBuffer *payload) {
    return false;
}
#endif
int tf_compass_create(TF_Compass *compass, const char *uid, TF_HAL *hal) {
    if (compass == NULL || uid == NULL || hal == NULL) {
        return TF_E_NULL;
    }

    memset(compass, 0, sizeof(TF_Compass));

    uint32_t numeric_uid;
    int rc = tf_base58_decode(uid, &numeric_uid);

    if (rc != TF_E_OK) {
        return rc;
    }

    uint8_t port_id;
    uint8_t inventory_index;
    rc = tf_hal_get_port_id(hal, numeric_uid, &port_id, &inventory_index);

    if (rc < 0) {
        return rc;
    }

    rc = tf_hal_get_tfp(hal, &compass->tfp, TF_COMPASS_DEVICE_IDENTIFIER, inventory_index);

    if (rc != TF_E_OK) {
        return rc;
    }

    compass->tfp->device = compass;
    compass->tfp->uid = numeric_uid;
    compass->tfp->cb_handler = tf_compass_callback_handler;
    compass->response_expected[0] = 0x03;

    return TF_E_OK;
}

int tf_compass_destroy(TF_Compass *compass) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    int result = tf_tfp_destroy(compass->tfp);
    compass->tfp = NULL;

    return result;
}

int tf_compass_get_response_expected(TF_Compass *compass, uint8_t function_id, bool *ret_response_expected) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    switch (function_id) {
        case TF_COMPASS_FUNCTION_SET_HEADING_CALLBACK_CONFIGURATION:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 0)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_SET_MAGNETIC_FLUX_DENSITY_CALLBACK_CONFIGURATION:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 1)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_SET_CONFIGURATION:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 2)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_SET_CALIBRATION:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 3)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_SET_WRITE_FIRMWARE_POINTER:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 4)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_SET_STATUS_LED_CONFIG:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 5)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_RESET:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 6)) != 0;
            }
            break;
        case TF_COMPASS_FUNCTION_WRITE_UID:
            if (ret_response_expected != NULL) {
                *ret_response_expected = (compass->response_expected[0] & (1 << 7)) != 0;
            }
            break;
        default:
            return TF_E_INVALID_PARAMETER;
    }

    return TF_E_OK;
}

int tf_compass_set_response_expected(TF_Compass *compass, uint8_t function_id, bool response_expected) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    switch (function_id) {
        case TF_COMPASS_FUNCTION_SET_HEADING_CALLBACK_CONFIGURATION:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 0);
            } else {
                compass->response_expected[0] &= ~(1 << 0);
            }
            break;
        case TF_COMPASS_FUNCTION_SET_MAGNETIC_FLUX_DENSITY_CALLBACK_CONFIGURATION:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 1);
            } else {
                compass->response_expected[0] &= ~(1 << 1);
            }
            break;
        case TF_COMPASS_FUNCTION_SET_CONFIGURATION:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 2);
            } else {
                compass->response_expected[0] &= ~(1 << 2);
            }
            break;
        case TF_COMPASS_FUNCTION_SET_CALIBRATION:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 3);
            } else {
                compass->response_expected[0] &= ~(1 << 3);
            }
            break;
        case TF_COMPASS_FUNCTION_SET_WRITE_FIRMWARE_POINTER:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 4);
            } else {
                compass->response_expected[0] &= ~(1 << 4);
            }
            break;
        case TF_COMPASS_FUNCTION_SET_STATUS_LED_CONFIG:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 5);
            } else {
                compass->response_expected[0] &= ~(1 << 5);
            }
            break;
        case TF_COMPASS_FUNCTION_RESET:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 6);
            } else {
                compass->response_expected[0] &= ~(1 << 6);
            }
            break;
        case TF_COMPASS_FUNCTION_WRITE_UID:
            if (response_expected) {
                compass->response_expected[0] |= (1 << 7);
            } else {
                compass->response_expected[0] &= ~(1 << 7);
            }
            break;
        default:
            return TF_E_INVALID_PARAMETER;
    }

    return TF_E_OK;
}

int tf_compass_set_response_expected_all(TF_Compass *compass, bool response_expected) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    memset(compass->response_expected, response_expected ? 0xFF : 0, 1);

    return TF_E_OK;
}

int tf_compass_get_heading(TF_Compass *compass, int16_t *ret_heading) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_HEADING, 0, 2, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_heading != NULL) { *ret_heading = tf_packet_buffer_read_int16_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 2); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_heading_callback_configuration(TF_Compass *compass, uint32_t period, bool value_has_to_change, char option, int16_t min, int16_t max) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_SET_HEADING_CALLBACK_CONFIGURATION, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_HEADING_CALLBACK_CONFIGURATION, 10, 0, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    period = tf_leconvert_uint32_to(period); memcpy(buf + 0, &period, 4);
    buf[4] = value_has_to_change ? 1 : 0;
    buf[5] = (uint8_t)option;
    min = tf_leconvert_int16_to(min); memcpy(buf + 6, &min, 2);
    max = tf_leconvert_int16_to(max); memcpy(buf + 8, &max, 2);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_heading_callback_configuration(TF_Compass *compass, uint32_t *ret_period, bool *ret_value_has_to_change, char *ret_option, int16_t *ret_min, int16_t *ret_max) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_HEADING_CALLBACK_CONFIGURATION, 0, 10, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_period != NULL) { *ret_period = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_value_has_to_change != NULL) { *ret_value_has_to_change = tf_packet_buffer_read_bool(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        if (ret_option != NULL) { *ret_option = tf_packet_buffer_read_char(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        if (ret_min != NULL) { *ret_min = tf_packet_buffer_read_int16_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 2); }
        if (ret_max != NULL) { *ret_max = tf_packet_buffer_read_int16_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 2); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_magnetic_flux_density(TF_Compass *compass, int32_t *ret_x, int32_t *ret_y, int32_t *ret_z) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_MAGNETIC_FLUX_DENSITY, 0, 12, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_x != NULL) { *ret_x = tf_packet_buffer_read_int32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_y != NULL) { *ret_y = tf_packet_buffer_read_int32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_z != NULL) { *ret_z = tf_packet_buffer_read_int32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_magnetic_flux_density_callback_configuration(TF_Compass *compass, uint32_t period, bool value_has_to_change) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_SET_MAGNETIC_FLUX_DENSITY_CALLBACK_CONFIGURATION, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_MAGNETIC_FLUX_DENSITY_CALLBACK_CONFIGURATION, 5, 0, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    period = tf_leconvert_uint32_to(period); memcpy(buf + 0, &period, 4);
    buf[4] = value_has_to_change ? 1 : 0;

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_magnetic_flux_density_callback_configuration(TF_Compass *compass, uint32_t *ret_period, bool *ret_value_has_to_change) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_MAGNETIC_FLUX_DENSITY_CALLBACK_CONFIGURATION, 0, 5, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_period != NULL) { *ret_period = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_value_has_to_change != NULL) { *ret_value_has_to_change = tf_packet_buffer_read_bool(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_configuration(TF_Compass *compass, uint8_t data_rate, bool background_calibration) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_SET_CONFIGURATION, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_CONFIGURATION, 2, 0, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    buf[0] = (uint8_t)data_rate;
    buf[1] = background_calibration ? 1 : 0;

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_configuration(TF_Compass *compass, uint8_t *ret_data_rate, bool *ret_background_calibration) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_CONFIGURATION, 0, 2, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_data_rate != NULL) { *ret_data_rate = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        if (ret_background_calibration != NULL) { *ret_background_calibration = tf_packet_buffer_read_bool(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_calibration(TF_Compass *compass, const int16_t offset[3], const int16_t gain[3]) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_SET_CALIBRATION, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_CALIBRATION, 12, 0, response_expected);

    size_t i;
    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    for (i = 0; i < 3; i++) { int16_t tmp_offset = tf_leconvert_int16_to(offset[i]); memcpy(buf + 0 + (i * sizeof(int16_t)), &tmp_offset, sizeof(int16_t)); }
    for (i = 0; i < 3; i++) { int16_t tmp_gain = tf_leconvert_int16_to(gain[i]); memcpy(buf + 6 + (i * sizeof(int16_t)), &tmp_gain, sizeof(int16_t)); }

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_calibration(TF_Compass *compass, int16_t ret_offset[3], int16_t ret_gain[3]) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_CALIBRATION, 0, 12, response_expected);

    size_t i;
    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_offset != NULL) { for (i = 0; i < 3; ++i) ret_offset[i] = tf_packet_buffer_read_int16_t(&compass->tfp->spitfp->recv_buf);} else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 6); }
        if (ret_gain != NULL) { for (i = 0; i < 3; ++i) ret_gain[i] = tf_packet_buffer_read_int16_t(&compass->tfp->spitfp->recv_buf);} else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 6); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_spitfp_error_count(TF_Compass *compass, uint32_t *ret_error_count_ack_checksum, uint32_t *ret_error_count_message_checksum, uint32_t *ret_error_count_frame, uint32_t *ret_error_count_overflow) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_SPITFP_ERROR_COUNT, 0, 16, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_error_count_ack_checksum != NULL) { *ret_error_count_ack_checksum = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_error_count_message_checksum != NULL) { *ret_error_count_message_checksum = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_error_count_frame != NULL) { *ret_error_count_frame = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        if (ret_error_count_overflow != NULL) { *ret_error_count_overflow = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_bootloader_mode(TF_Compass *compass, uint8_t mode, uint8_t *ret_status) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_BOOTLOADER_MODE, 1, 1, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    buf[0] = (uint8_t)mode;

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_status != NULL) { *ret_status = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_bootloader_mode(TF_Compass *compass, uint8_t *ret_mode) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_BOOTLOADER_MODE, 0, 1, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_mode != NULL) { *ret_mode = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_write_firmware_pointer(TF_Compass *compass, uint32_t pointer) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_SET_WRITE_FIRMWARE_POINTER, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_WRITE_FIRMWARE_POINTER, 4, 0, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    pointer = tf_leconvert_uint32_to(pointer); memcpy(buf + 0, &pointer, 4);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_write_firmware(TF_Compass *compass, const uint8_t data[64], uint8_t *ret_status) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_WRITE_FIRMWARE, 64, 1, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    memcpy(buf + 0, data, 64);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_status != NULL) { *ret_status = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_set_status_led_config(TF_Compass *compass, uint8_t config) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_SET_STATUS_LED_CONFIG, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_SET_STATUS_LED_CONFIG, 1, 0, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    buf[0] = (uint8_t)config;

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_status_led_config(TF_Compass *compass, uint8_t *ret_config) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_STATUS_LED_CONFIG, 0, 1, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_config != NULL) { *ret_config = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_chip_temperature(TF_Compass *compass, int16_t *ret_temperature) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_CHIP_TEMPERATURE, 0, 2, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_temperature != NULL) { *ret_temperature = tf_packet_buffer_read_int16_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 2); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_reset(TF_Compass *compass) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_RESET, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_RESET, 0, 0, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_write_uid(TF_Compass *compass, uint32_t uid) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_compass_get_response_expected(compass, TF_COMPASS_FUNCTION_WRITE_UID, &response_expected);
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_WRITE_UID, 4, 0, response_expected);

    uint8_t *buf = tf_tfp_get_payload_buffer(compass->tfp);

    uid = tf_leconvert_uint32_to(uid); memcpy(buf + 0, &uid, 4);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_read_uid(TF_Compass *compass, uint32_t *ret_uid) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_READ_UID, 0, 4, response_expected);

    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        if (ret_uid != NULL) { *ret_uid = tf_packet_buffer_read_uint32_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 4); }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}

int tf_compass_get_identity(TF_Compass *compass, char ret_uid[8], char ret_connected_uid[8], char *ret_position, uint8_t ret_hardware_version[3], uint8_t ret_firmware_version[3], uint16_t *ret_device_identifier) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (tf_hal_get_common((TF_HAL *)compass->tfp->hal)->locked) {
        return TF_E_LOCKED;
    }

    bool response_expected = true;
    tf_tfp_prepare_send(compass->tfp, TF_COMPASS_FUNCTION_GET_IDENTITY, 0, 25, response_expected);

    size_t i;
    uint32_t deadline = tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + tf_hal_get_common((TF_HAL *)compass->tfp->hal)->timeout;

    uint8_t error_code = 0;
    int result = tf_tfp_transmit_packet(compass->tfp, response_expected, deadline, &error_code);

    if (result < 0) {
        return result;
    }

    if (result & TF_TICK_TIMEOUT) {
        return TF_E_TIMEOUT;
    }

    if (result & TF_TICK_PACKET_RECEIVED && error_code == 0) {
        char tmp_connected_uid[8] = {0};
        if (ret_uid != NULL) { tf_packet_buffer_pop_n(&compass->tfp->spitfp->recv_buf, (uint8_t*)ret_uid, 8);} else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 8); }
        tf_packet_buffer_pop_n(&compass->tfp->spitfp->recv_buf, (uint8_t*)tmp_connected_uid, 8);
        if (ret_position != NULL) { *ret_position = tf_packet_buffer_read_char(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 1); }
        if (ret_hardware_version != NULL) { for (i = 0; i < 3; ++i) ret_hardware_version[i] = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf);} else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 3); }
        if (ret_firmware_version != NULL) { for (i = 0; i < 3; ++i) ret_firmware_version[i] = tf_packet_buffer_read_uint8_t(&compass->tfp->spitfp->recv_buf);} else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 3); }
        if (ret_device_identifier != NULL) { *ret_device_identifier = tf_packet_buffer_read_uint16_t(&compass->tfp->spitfp->recv_buf); } else { tf_packet_buffer_remove(&compass->tfp->spitfp->recv_buf, 2); }
        if (tmp_connected_uid[0] == 0 && ret_position != NULL) {
            *ret_position = tf_hal_get_port_name((TF_HAL *)compass->tfp->hal, compass->tfp->spitfp->port_id);
        }
        if (ret_connected_uid != NULL) {
            memcpy(ret_connected_uid, tmp_connected_uid, 8);
        }
        tf_tfp_packet_processed(compass->tfp);
    }

    result = tf_tfp_finish_send(compass->tfp, result, deadline);

    if (result < 0) {
        return result;
    }

    return tf_tfp_get_error(error_code);
}
#if TF_IMPLEMENT_CALLBACKS != 0
int tf_compass_register_heading_callback(TF_Compass *compass, TF_Compass_HeadingHandler handler, void *user_data) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (handler == NULL) {
        compass->tfp->needs_callback_tick = false;
        compass->tfp->needs_callback_tick |= compass->magnetic_flux_density_handler != NULL;
    } else {
        compass->tfp->needs_callback_tick = true;
    }

    compass->heading_handler = handler;
    compass->heading_user_data = user_data;

    return TF_E_OK;
}


int tf_compass_register_magnetic_flux_density_callback(TF_Compass *compass, TF_Compass_MagneticFluxDensityHandler handler, void *user_data) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    if (handler == NULL) {
        compass->tfp->needs_callback_tick = false;
        compass->tfp->needs_callback_tick |= compass->heading_handler != NULL;
    } else {
        compass->tfp->needs_callback_tick = true;
    }

    compass->magnetic_flux_density_handler = handler;
    compass->magnetic_flux_density_user_data = user_data;

    return TF_E_OK;
}
#endif
int tf_compass_callback_tick(TF_Compass *compass, uint32_t timeout_us) {
    if (compass == NULL) {
        return TF_E_NULL;
    }

    return tf_tfp_callback_tick(compass->tfp, tf_hal_current_time_us((TF_HAL *)compass->tfp->hal) + timeout_us);
}

#ifdef __cplusplus
}
#endif
