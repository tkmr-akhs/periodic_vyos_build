#!/usr/bin/python3
import datetime
import glob
import hashlib
import io
import json
import os
import re
import sys
import traceback
import zipfile
from logging import error, getLogger
from logging.config import dictConfig

import requests
import tomli
from bs4 import BeautifulSoup

import periodic_vyos_build_lib as lib

EXIT_CODE_NORMAL = 0
EXIT_CODE_GENERAL_ERROR = -1
EXIT_CODE_OLD_KERNEL = 1
EXIT_CODE_NOW_BUILDING = 2
EXIT_CODE_BUILD_TIMED_OUT = 3
EXIT_CODE_BUILD_FAILURE = 4
RETRY_MAX = 10

FILE_ENCODE = "utf-8"
FILE_VYOS_IMAGE_BUILDING_HASH = "hash_vyos_building.txt"
FILE_VYOS_IMAGE_BUILT_HASH = "last_hash_vi.txt"
FILE_PI_KERNEL_BUILDING_VER = "ver_pi_building.txt"
FILE_PI_KERNEL_BUILT_VER = "ver_pi_built.txt"


def stop_container() -> None:
    """Stop all Docker containers

    Stop all Docker containers that originate from the "vyos/vyos-build:sagitta-arm64" ancestor\
    image.
    """
    os.system(
        'sudo docker stop $(sudo docker ps -a -q --filter "ancestor=vyos/vyos-build:sagitta-arm64")'
    )


def get_vyos_require_kernel_version(data: bytes) -> str:
    """Gets the kernel version required by VyOS.

    Args:
        data (bytes): The default.toml obtained from GitHub.

    Returns:
        str: The kernel version required by VyOS.
    """
    default_toml = tomli.load(io.BytesIO(data))
    return default_toml["kernel_version"]


def get_newest_pi_kernel_version(data: bytes) -> str:
    """Gets the version of the latest kernel released for Raspberry Pi.

    Args:
        data (bytes): The Makefile obtained from GitHub.

    Returns:
        str: The version of the latest kernel released for Raspberry Pi.
    """
    result: str = None

    version_re = re.compile("(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION) = (.*)")
    for line in data.splitlines():
        re_result = version_re.match(line.decode())
        # print(line.decode())
        if not re_result:
            # print(f"skip: {line.decode()}")
            continue

        if re_result.group(1) == "VERSION":
            result = re_result.group(2)
        elif re_result.group(1) in ("PATCHLEVEL", "SUBLEVEL"):
            result = result + "." + re_result.group(2)
        elif re_result.group(1) == "EXTRAVERSION":
            exver = re_result.group(2)
            if exver:
                result = result + "-" + exver
            break

    return result


def get_new_iso_url(html: bytes) -> str:
    """Extract the latest ISO URL from VyOS page.

    Extract the latest ISO URL from the provided HTML content of the VyOS nightly builds GitHub\
    page.

    Args:
        html (str): The HTML content of the VyOS nightly builds GitHub page.

    Returns:
        str: The URL of the latest VyOS nightly build ISO.
    """
    result: list[str] = []
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.select("a"):
        href = anchor.get("href")
        if href.endswith(".iso"):
            result.append(href)

    result.sort(reverse=True)
    return result[0]


def load_tmp_data(tmp_file: str) -> str:
    """Load the provided hash to the specified file.

    Args:
        tmp_file (str): Path to the file where the data is stored.

    Returns:
        str: The data string to be loaded.
    """
    try:
        with open(tmp_file, "r", encoding=FILE_ENCODE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def save_tmp_data(tmp_file: str, current_data: str) -> None:
    """Save the provided hash to the specified file.

    Args:
        tmp_file (str): Path to the file where the data should be stored.
        current_data (str): The data string to be saved.
    """
    with open(tmp_file, "w", encoding=FILE_ENCODE) as f:
        f.write(current_data)


def get_html(url: str, timeout: float) -> bytes:
    """Retrieve the HTML content of the specified URL.

    Args:
        url (str): The URL to fetch the HTML content from.
        timeout (float): The maximum time, in seconds, to wait for the server's response.

    Returns:
        bytes: The HTML content of the specified URL.
    """
    response = requests.get(url, timeout=timeout)
    return response.content


class OutdatedKernelException(Exception):
    """Exception raised when the kernel is outdated."""

    def __init__(self, vyos_kernel: str, pi_kernel: str, *args: object) -> None:
        """Initializer

        Args:
            vyos_kernel (str):
            pi_kernel (str):
        """
        super().__init__(*args)
        self.vyos_kernel = vyos_kernel
        self.pi_kernel = pi_kernel


class KernelBuildingException(Exception):
    """Exception raised when the kernel is currently being built."""

    def __init__(self, pi_kernel: str, *args: object) -> None:
        """Initializer

        Args:
            pi_kernel (str):
        """
        super().__init__(*args)
        self.pi_kernel = pi_kernel


class KernelBuildFailureException(Exception):
    """Exception raised when the kernel build fails."""

    def __init__(self, output: str, *args: object) -> None:
        """Initializer

        Args:
            output (str): output of the command that caused the failure.
        """
        super().__init__(*args)
        self.output = output


class VyOSBuildingException(Exception):
    """Exception raised when the VyOS is currently being built."""


class VyOSBuildFailureException(Exception):
    """Exception raised when the VyOS build fails."""

    def __init__(self, output: str, *args: object) -> None:
        """Initializer

        Args:
            output (str): output of the command that caused the failure.
        """
        super().__init__(*args)
        self.output = output


class Main:
    """Class for the program's entry point."""

    def __init__(self, args: list[str]) -> None:
        """Initializer

        Args:
            args (list[str]): List of command line arguments.
        """
        # Parse command line arguments
        cli_cnf = lib.get_cli_cnf(args)

        # Prepare ConfigurationLoader
        cnf_loader = lib.ConfigurationLoader(cli_cnf["common"]["cnf_dirpath"])

        # Get application configuration
        try:
            self._app_cnf = cnf_loader.get_app_cnf(cli_cnf)
        except lib.CnfError as cnf_error:
            # Logging configuration is not yet complete at this point, so output as root ERROR.
            error(str(cnf_error))
            raise cnf_error

        # Get logging configuration
        log_cnf = cnf_loader.get_log_cnf(self._app_cnf)

        # Set logging configuration
        dictConfig(log_cnf)
        self._logger = getLogger(__name__)

        # Initialize application (create tmp directory, etc.)
        lib.init_app(self._app_cnf)

        #
        self._mail_sender = lib.MailSender(
            self._app_cnf["mail"]["smtp_server"],
            self._app_cnf["mail"]["smtp_port"],
            self._app_cnf["mail"]["smtp_localhost"],
            self._app_cnf["mail"]["smtp_user"],
            self._app_cnf["mail"]["smtp_password"],
            self._app_cnf["mail"]["smtp_tls"],
            self._app_cnf["mail"]["from_addr"],
        )
        self._to_addr = self._app_cnf["mail"]["to_addr"]
        self._tmp_dirpath = os.path.expanduser(self._app_cnf["common"]["tmp_dirpath"])
        self._wrk_dirpath = os.path.expanduser(self._app_cnf["common"]["wrk_dirpath"])
        self._pub_dirpath = os.path.expanduser(self._app_cnf["common"]["pub_dirpath"])
        self._url_vyos_image = self._app_cnf["common"]["url_vyos_image"]
        self._url_vyos_kernel = self._app_cnf["common"]["url_vyos_kernel"]
        self._url_pi_kernel = self._app_cnf["common"]["url_pi_kernel"]
        self._page_timeout = self._app_cnf["common"]["page_timeout"]
        self._download_timeout = self._app_cnf["common"]["download_timeout"]
        self._file_vyos_image_building_hash = os.path.join(
            self._tmp_dirpath, FILE_VYOS_IMAGE_BUILDING_HASH
        )
        self._file_vyos_image_built_hash = os.path.join(
            self._tmp_dirpath, FILE_VYOS_IMAGE_BUILT_HASH
        )
        self._file_pi_kernel_building_ver = os.path.join(
            self._tmp_dirpath, FILE_PI_KERNEL_BUILDING_VER
        )
        self._file_pi_kernel_built_ver = os.path.join(
            self._tmp_dirpath, FILE_PI_KERNEL_BUILT_VER
        )

    def _send_notif(
        self,
        subject: str,
        message: str,
        attachments: list[str],
        start_datetime: datetime.datetime,
        is_err: bool = True,
    ) -> None:
        """
        Logs the specified subject and sends an email to the specified recipient.

        Args:
            subject (str): The subject of the email.
            message (str): The body of the email.
            attachments (list[str]): List of files to be attached to the email.
            start_datetime (datetime.datetime): The date and time when the processing was started.
            is_err (bool, optional): Whether to output as an error log. Default is True (output as error).
        """
        if is_err:
            self._logger.error(subject)
        else:
            self._logger.info(subject)

        end_datetime = datetime.datetime.now()
        elapsed_time = end_datetime - start_datetime
        self._mail_sender.send_mail(
            self._to_addr,
            subject,
            "\n".join(
                (
                    f"start_datetime: {start_datetime}",
                    f"end_datetime: {end_datetime}",
                    f"elapsed_time: {elapsed_time}",
                    message,
                )
            ),
            attachments,
        )

    def execute(self) -> int:
        """Main execution method.

        Returns:
            int: Exit code indicating the result of the execution.
        """
        current_hash_v = ""
        start_datetime = datetime.datetime.now()
        try:
            os.chdir(self._wrk_dirpath)
            is_kernel_build_required, pi_kernel_ver = self._check_kernel()

            if is_kernel_build_required:
                for i in range(RETRY_MAX):
                    try:
                        self._build_kernel(pi_kernel_ver)
                        break
                    except lib.KeywordTimedOutException as exp:
                        if i >= RETRY_MAX - 1:
                            self._send_notif(
                                f"Creation of vyos-rpi.img.zip failed due to a timeout in the '{exp.command}' command.",
                                f"ビルドに失敗しました。 '{exp.command}' コマンドでタイムアウトしました。\n{exp.output}",
                                [],
                                start_datetime,
                            )
                            return EXIT_CODE_BUILD_TIMED_OUT

                self._send_notif(
                    f"Kernel {pi_kernel_ver} was built",
                    f"カーネル {pi_kernel_ver} をビルドしました。",
                    [],
                    start_datetime,
                    False,
                )

                return EXIT_CODE_NORMAL
            else:
                is_new_vyos, current_hash_v = self._check_vyos()
                if not is_new_vyos:
                    return EXIT_CODE_NORMAL

                for i in range(RETRY_MAX):
                    try:
                        self._build_img(current_hash_v)
                        break
                    except lib.KeywordTimedOutException as exp:
                        if i >= RETRY_MAX - 1:
                            self._send_notif(
                                f"Creation of vyos-rpi.img.zip failed due to a timeout in the '{exp.command}' command.",
                                f"ビルドに失敗しました。 '{exp.command}' コマンドでタイムアウトしました。\n{exp.output}",
                                [],
                                start_datetime,
                            )
                            return EXIT_CODE_BUILD_TIMED_OUT

                archived_files = self._archive_img()

                self._publish_files(archived_files)

                self._send_notif(
                    "vyos-rpi.img.zip created",
                    "vyos-rpi.img を作成しました。",
                    [],
                    start_datetime,
                    False,
                )

                return EXIT_CODE_NORMAL
        except OutdatedKernelException as exp:
            self._send_notif(
                f"A new kernel '{exp.vyos_kernel}' is required by VyOS. The currently released kernel is '{exp.pi_kernel}'.",
                f"新しいカーネル {exp.vyos_kernel} が必要とされました。現在リリース済みのカーネルは {exp.pi_kernel} です",
                [],
                start_datetime,
            )
            return EXIT_CODE_OLD_KERNEL
        except KernelBuildingException as exp:
            self._send_notif(
                "Kernel package is now being built.",
                f"カーネル パッケージ {exp.pi_kernel} がビルド中です。",
                [],
                start_datetime,
            )
            return EXIT_CODE_NOW_BUILDING
        except KernelBuildFailureException as exp:
            self._send_notif(
                "Creation of kernel failed.",
                f"カーネルのビルドに失敗しました。\n{exp.output}",
                [],
                start_datetime,
            )
            return EXIT_CODE_BUILD_FAILURE
        except lib.CommandTimedOutException as exp:
            self._send_notif(
                f"Creation of vyos-rpi.img.zip failed due to a timeout in the '{exp.command}' command.",
                f"ビルドに失敗しました。 '{exp.command}' コマンドでタイムアウトしました。\n{exp.output}",
                [],
                start_datetime,
            )
            return EXIT_CODE_BUILD_TIMED_OUT
        except VyOSBuildingException as exp:
            self._send_notif(
                "VyOS is now being built.",
                "VyOS がビルド中です。",
                [],
                start_datetime,
            )
            return EXIT_CODE_NOW_BUILDING
        except VyOSBuildFailureException as exp:
            self._send_notif(
                "Creation of vyos-rpi.img.zip failed.",
                f"ビルドに失敗しました。\n{exp.output}",
                [],
                start_datetime,
            )
            # save_tmp_data(self._hash_file_vyos_image, current_hash_v)
            return EXIT_CODE_BUILD_FAILURE
        except Exception:
            subject = "vyos-py-build: An error occurred during execution."
            message = (
                "実行中に例外が発生しました。\n"
                + "- - - - - - - -\n"
                + traceback.format_exc(limit=None, chain=True)
            )
            self._logger.exception(subject)
            self._mail_sender.send_mail(self._to_addr, subject, message, [])
            return EXIT_CODE_GENERAL_ERROR

    def _check_kernel(self) -> tuple[bool, str]:
        """Checks for Raspberry Pi kernel release.

        Checks if a new Linux kernel for Raspberry Pi has been released.

        Returns:
            tuple[bool, str]: Whether a kernel build is necessary, and the version of the latest Raspberry Pi kernel release.

        Raises:
            KernelBuildingException
                Raised if the kernel is currently being built.
            OutdatedKernelException
                Raised if a new kernel is needed.
        """
        self._logger.debug("Checking kernel release.")

        prev_building = load_tmp_data(self._file_pi_kernel_building_ver)
        prev_built = load_tmp_data(self._file_pi_kernel_built_ver)

        # Retrieve file from github with http.
        html_pi_kernel = get_html(self._url_pi_kernel, self._page_timeout)
        html_vyos_kernel = get_html(self._url_vyos_kernel, self._page_timeout)

        current_vyos_kernel_ver = get_vyos_require_kernel_version(html_vyos_kernel)
        current_pi_kernel_ver = get_newest_pi_kernel_version(html_pi_kernel)

        if current_vyos_kernel_ver == prev_built:
            self._logger.debug(
                "_check_kernel: False, current_vyos_kernel_ver: '%s', prev_built: '%s'",
                current_vyos_kernel_ver,
                prev_built,
            )
            return False, None

        if current_vyos_kernel_ver == current_pi_kernel_ver:
            if current_pi_kernel_ver == prev_building:
                raise KernelBuildingException(current_pi_kernel_ver)
            else:
                self._logger.debug(
                    "_check_kernel: True, current_pi_kernel_ver: '%s', prev_built: '%s'",
                    current_pi_kernel_ver,
                    prev_built,
                )
                return True, current_pi_kernel_ver
        else:
            raise OutdatedKernelException(
                current_vyos_kernel_ver, current_pi_kernel_ver
            )

    def _build_kernel(self, kernel_ver: str) -> None:
        """Build a kernel package for Raspberry Pi.

        Args:
            kernel_ver (str):

        Raises:
            CommandTimedOutException:
                Raised if the build command times out.
        """
        self._logger.info("Building new kernel package.")
        try:
            save_tmp_data(self._file_pi_kernel_building_ver, kernel_ver)

            # Execute the commands
            self._logger.debug("make kernel-registry.")
            output = lib.run_command_with_timeout(
                ["make", "kernel-registry"],
                720 * 60,
                "useradd warning: vyos_bld's uid 0 outside of the UID_MIN 1000 and UID_MAX 60000 range.",
                60,
                finalizer_func=stop_container,
            )
            save_tmp_data(self._file_pi_kernel_built_ver, kernel_ver)
        finally:
            os.remove(self._file_pi_kernel_building_ver)

        # Check for file existence
        filepaths = [
            f for f in glob.glob("build/linux-image-*.deb") if os.path.isfile(f)
        ]
        if len(filepaths) < 1:
            os.remove(self._file_pi_kernel_built_ver)
            raise KernelBuildFailureException(output)

    def _check_vyos(self) -> tuple[bool, str]:
        """Check for new VyOS releases.

        Checks if a new VyOS has been released.

        Returns:
            tuple[bool, str, str]: Whether there is a new release, current hash, and arm64 version ISO URL.

        Raises:
            VyOSBuildingException
                Raised if VyOS is currently being built.
        """
        self._logger.debug("Checking for VyOS release.")

        prev_building = load_tmp_data(self._file_vyos_image_building_hash)
        prev_built = load_tmp_data(self._file_vyos_image_built_hash)

        # Compare the current and previous versions
        current_hash = lib.get_git_remote_head("vyos-build", "sagitta")

        if current_hash == prev_built:
            self._logger.info(
                "No new releases of VyOS are available. (built is %s)", prev_built
            )
            return False, None

        if current_hash and current_hash == prev_building:
            raise VyOSBuildingException()

        self._logger.info(
            "New releases of VyOS are available. (built: %s, to be built: %s)",
            prev_built,
            current_hash,
        )
        return True, current_hash

    def _build_img(self, vyos_hash: str) -> None:
        """Build a VyOS image for Raspberry Pi.

        Builds a VyOS image for Raspberry Pi. After building, a zip file of the generated image will also be created (2 in total, one for rpi 4b and one for rpi cm4).

        Args:
            vyos_hash (str):

        Raises:
            CommandTimedOutException:
                Raised if the build command times out.
            VyOSBuildFailureException:
                Raised if the build fails and no zip file is generated.
        """
        self._logger.info("Building new VyOS image.")
        try:
            save_tmp_data(self._file_vyos_image_building_hash, vyos_hash)

            # Execute the commands
            self._logger.debug("make iso-registry.")
            output = lib.run_command_with_timeout(
                ["make", "iso-registry"],
                140 * 60,
                "useradd warning: vyos_bld's uid 0 outside of the UID_MIN 1000 and UID_MAX 60000 range.",
                60,
                finalizer_func=stop_container,
            )
            save_tmp_data(self._file_vyos_image_built_hash, vyos_hash)
        finally:
            os.remove(self._file_vyos_image_building_hash)

        # Check for file existence
        filepaths = [f for f in glob.glob("vyos-bcm271*.img.zip") if os.path.isfile(f)]
        if len(filepaths) < 2:
            raise VyOSBuildFailureException(output)

    def _archive_img(self) -> None:
        """Archive VyOS images.

        Renames the zip files containing the VyOS images for Raspberry Pi with the current date. Also, downloads the amd64 ISO from the specified URL and zips it with the current date.

        Args:
            iso_url (str): The URL of the amd64 VyOS ISO to be downloaded.

        Returns:
            List of archived files.
        """
        self._logger.debug("Archiving images.")
        archived_files: list[str] = []

        self._logger.debug("Renaming vyos-pi zip.")
        filepaths = [f for f in glob.glob("vyos-bcm271*.img.zip") if os.path.isfile(f)]
        for filepath in filepaths:
            new_filepath = f"{os.path.splitext(filepath)[0]}.{datetime.date.today():%Y-%m-%d}{os.path.splitext(filepath)[1]}"
            os.rename(filepath, new_filepath)
            archived_files.append(new_filepath)

        return archived_files

    def _publish_files(self, files: list[str]):
        """Move archived files to the public directory.

        Args:
            files (list[str]): Archived files.
        """
        self._logger.info("Publishing vyos images.")
        for file in files:
            os.rename(file, os.path.join(self._pub_dirpath, file))


if __name__ == "__main__":
    main_obj = Main(sys.argv)
    sys.exit(main_obj.execute())
