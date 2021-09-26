#include <csignal>
#include <cstring>
#include <iomanip>
#include <libcryptsetup.h>
#include <openssl/sha.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <tss2/tss2_esys.h>
#include <unistd.h>

// Duration to check dm-verity status.
constexpr size_t DURATION = 10;
constexpr ESYS_TR PCR = ESYS_TR_PCR10;

// Value for extending with something to destory validity.
const std::string INVALID_VALUE = "INVALID";

volatile sig_atomic_t running = 1;
void handler(int signum) { running = 0; };

TPML_DIGEST_VALUES construct_tpm_digest(const std::string &value) {
  TPML_DIGEST_VALUES values;
  SHA256_CTX ctx;
  auto digest = values.digests[0].digest.sha256;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, value.c_str(), value.size());
  SHA256_Final(digest, &ctx);

  values.count = 1;
  values.digests[0].hashAlg = TPM2_ALG_SHA256;

  return values;
}

bool tpm_write(const std::string value, ESYS_TR pcr) {
  ESYS_CONTEXT *ctx;

  if (TSS2_RC_SUCCESS != Esys_Initialize(&ctx, NULL, NULL)) {
    spdlog::error("Could not initialize TPM context!");
    return false;
  }

  TPML_DIGEST_VALUES digest = construct_tpm_digest(value);

  bool success =
      TSS2_RC_SUCCESS == Esys_PCR_Extend(ctx, pcr, ESYS_TR_PASSWORD,
                                         ESYS_TR_NONE, ESYS_TR_NONE, &digest);
  if (!success) {
    spdlog::error("Could not extend pcr register");
  }

  Esys_Finalize(&ctx);
  return success;
}

/**
 * We use libcryptsetup api instead of talking to ioctl directly.
 * They have better error handling etc.
 * This will print some info if something goes wrong.
 *
 **/
bool get_verity_status(const std::string name) {
  crypt_device *cd;
  struct crypt_active_device data;
  bool status = false;
  if (crypt_init_by_name(&cd, name.c_str())) {
    spdlog::error("Could not find device: {}", name);
    return false;
  }

  if (strcmp(crypt_get_type(cd), CRYPT_VERITY) == 0) {
    crypt_get_active_device(cd, name.c_str(), &data);
    status = !(data.flags & CRYPT_ACTIVATE_CORRUPTED);
  } else {
    spdlog::error("Device is not a verity device!");
  }

  crypt_free(cd);
  return status;
}

std::string get_root_hash(std::string name) {
  crypt_device *cd;
  std::stringstream root_hash_hex;
  if (crypt_init_by_name(&cd, name.c_str())) {
    spdlog::error("Could not find device: {}", name);
    return INVALID_VALUE;
  }
  size_t size = crypt_get_volume_key_size(cd);
  std::vector<char> root_hash(size);
  if (size > 0) {
    // The name is missleading it will return the root_hash if cd is from type
    // VERITY.
    if (!crypt_volume_key_get(cd, CRYPT_ANY_SLOT, root_hash.data(), &size, NULL,
                              0)) {
      // Convert bytes into hex string.
      for (int i = 0; i < size; i++) {
        root_hash_hex << std::hex << std::setw(2) << std::setfill('0')
            << (root_hash[i] & 0xFF);
      }
    }
  }
  return root_hash_hex.str();
}

bool extend_and_log(const std::string extend, ESYS_TR pcr) {
  spdlog::info("Extending PCR {} with: \"{}\"", pcr, extend);
  spdlog::get("pcr")->info(extend);
  return tpm_write(extend, pcr);
}

void loop(size_t sleep_duration, const std::string device, ESYS_TR pcr) {
  std::string root_hash = get_root_hash(device);
  bool last_status = true;
  bool first_run = true;

  while (running) {
    bool good = get_verity_status(device);
    std::string status = good ? "valid" : "corrupted";
    spdlog::info("Status of {} is {}.", device, status);
    // Only log on change
    if (good != last_status || first_run) {
      last_status = good;
      std::string extend = device + " " + root_hash + " " + status;
      extend_and_log(extend, pcr);
    }
    sleep(sleep_duration);
    first_run = false;
  }

  spdlog::info("Program exited. Extend TPM with invalid value.");
  tpm_write(INVALID_VALUE, pcr);
}

/**
 * Use our logger also for errors that come from cryptsetup.
 **/
void cryptsetup_logger(int level, const char *msg, void *usrptr) {
  std::string_view message(
      msg, strlen(msg) - 1); // Remove last char which is always a newline.
  switch (level) {
  case CRYPT_LOG_NORMAL:
    spdlog::info(message);
    break;
  case CRYPT_LOG_ERROR:
    spdlog::error(message);
    break;
  case CRYPT_LOG_VERBOSE:
  case CRYPT_LOG_DEBUG:
  case CRYPT_LOG_DEBUG_JSON:
    spdlog::debug(message);
    break;
  default:
    spdlog::info(message);
    break;
  }
}

/**
 * Setup logger for pcr.log
 * Flush every time and dont log timestamp and level etc.
 **/
bool logger_setup(std::string log_path, ESYS_TR pcr) {
  // Attach our logger to the cryptsetup libary
  crypt_set_log_callback(NULL, cryptsetup_logger, NULL);

  // Try to create the logger for the logfile
  try {
    auto pcr_log = spdlog::basic_logger_mt("pcr", log_path, true);
    pcr_log->set_pattern("%v"); 
    pcr_log->flush_on(spdlog::level::info);
  } catch (const spdlog::spdlog_ex &ex) {
    spdlog::error("Log init failed: {}", ex.what());
    tpm_write(INVALID_VALUE, pcr);
    return false;
  };

  return true;
}

int main(int argc, char const *argv[]) {
  std::signal(SIGINT, handler);

  if (geteuid() != 0) {
    spdlog::error("This application needs to be run as root!");
    return EXIT_FAILURE;
  }

  if (argc != 3) {
    spdlog::error("Please specify device path and log path!");
    return EXIT_FAILURE;
  }

  std::string device(argv[1]);
  std::string log_path(argv[2]);
  spdlog::info("Startup with device: \"{}\" and log: \"{}\"", device, log_path);

  if (!logger_setup(log_path, PCR)) {
    return EXIT_FAILURE;
  }

  loop(DURATION, device, PCR);

  return EXIT_SUCCESS;
}
