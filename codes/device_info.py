import platform
import subprocess
from hash_utils import hash_combined_info


def get_device_name():
    device_name = "Unknown"

    try:
        system = platform.system()

        if system == "Windows":
            device_name = platform.node()
        elif system == "Linux":
            output = subprocess.check_output("uname -n", shell=True).decode().strip()
            device_name = output if output else "Unknown"
        elif system == "Darwin":
            device_name = platform.node()
        elif system == "Java":
            try:
                import android
                droid = android.Android()
                device_name = droid.getSystemProperty("ro.product.model")[0]
            except ImportError:
                device_name = "Android module not available"
            except Exception as e:
                device_name = str(e)
        else:
            device_name = "Unsupported OS"
    except Exception as e:
        device_name = str(e)

    return device_name


def get_cpu_serial_number():
    serial_number = "Unknown"
    try:
        system = platform.system()
        if system == "Windows":
            output = subprocess.check_output("wmic cpu get ProcessorId", shell=True).decode()
            serial_number = output.split("\n")[1].strip()
        elif system == "Linux":
            output = subprocess.check_output("sudo dmidecode -t processor | grep 'ID'", shell=True).decode()
            serial_number = output.split(":")[1].strip()
        elif system == "Darwin":
            output = subprocess.check_output("system_profiler SPHardwareDataType | grep 'Serial Number (system)'", shell=True).decode()
            serial_number = output.split(":")[1].strip()
        elif system == "Java":
            import android
            droid = android.Android()
            serial_number = droid.getSystemProperty("ro.serialno")[0]
        else:
            serial_number = "Unsupported OS"
    except Exception as e:
        serial_number = str(e)
    return serial_number


def generate_serial_number():
    user_info = get_device_name()
    cpu_info = get_cpu_serial_number()
    serial_number = hash_combined_info(user_info, cpu_info)
    return serial_number
