import argparse
import os
import pathlib
import select
import smtplib
import subprocess
import time
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from logging import (
    CRITICAL,
    DEBUG,
    ERROR,
    FATAL,
    INFO,
    NOTSET,
    WARNING,
    Filter,
    LogRecord,
    getLevelName,
)
from typing import Any, Callable

import tomli

CNF_DIR = "~/etc/periodic_vyos_build"
APP_CNF = "config.toml"
LOG_CNF = "logging.toml"


class CnfError(Exception):
    """Exception raised when there is a problem with the configuration."""


class ConfigurationLoader:
    """Class for loading configurations"""

    def __init__(
        self,
        cnf_dir: str = CNF_DIR,
        app_cnf_file: str = APP_CNF,
        log_cnf_file: str = LOG_CNF,
    ) -> None:
        """Initializer

        Args:
            cnf_dir (str, optional): Directory where config files are located. Defaults to CNF_DIR.
            default_cnf (str, optional): Default config file name. Defaults to DEFAULT_CNF.
            usr_cnf (str, optional):\
                Name of config file for user customization. Defaults to USR_CNF.
            log_cnf (str, optional): Logging config file name. Defaults to LOG_CNF.
        """
        if cnf_dir is None:
            cnf_dir = CNF_DIR
        if app_cnf_file is None:
            app_cnf_file = APP_CNF
        if log_cnf_file is None:
            log_cnf_file = LOG_CNF

        self._cnf_dir = os.path.expanduser(cnf_dir)
        self._default_cnf = app_cnf_file
        self._log_cnf = log_cnf_file

    def get_app_cnf(self, cli_cnf: dict) -> dict:
        """Get app configuration.

        Args:
            cli_cnf: Configuration by command line arguments

        Returns:
            dict: App configuration

        Raises:
            CnfError: Config validation failed.
        """
        # with open(os.path.join(self._cnf_dir, self._default_cnf), mode="rb") as fp:
        #     app_cnf = tomllib.load(fp)
        with open(os.path.join(self._cnf_dir, self._default_cnf), mode="rb") as fp:
            app_cnf = tomli.load(fp)

        recursive_merge(app_cnf, cli_cnf)

        validate_app_cnf(app_cnf)

        return app_cnf

    def get_log_cnf(self, app_cnf: dict[str, Any]) -> dict:
        """Get logging configuration.

        Returns:
            dict: Logging configuration
        """

        class _LevelOrHigherDiscardFilter(Filter):
            def __init__(self, level: str) -> None:
                super().__init__()
                self._level = getLevelNamesMapping().get(level, NOTSET)

            def filter(self, record: LogRecord) -> bool:
                return record.levelno < self._level

        # with open(os.path.join(self._cnf_dir, self._log_cnf), mode="rb") as fp:
        #     log_cnf = tomllib.load(fp)
        with open(os.path.join(self._cnf_dir, self._log_cnf), mode="rb") as fp:
            log_cnf = tomli.load(fp)

        log_cnf["filters"]["levelOrHigherDiscardFilter"][
            "()"
        ] = _LevelOrHigherDiscardFilter

        return log_cnf


def getLevelNamesMapping():
    return {
        "CRITICAL": CRITICAL,
        "FATAL": FATAL,
        "ERROR": ERROR,
        "WARN": WARNING,
        "WARNING": WARNING,
        "INFO": INFO,
        "DEBUG": DEBUG,
        "NOTSET": NOTSET,
    }


def validate_app_cnf(cnf: dict) -> None:
    """Validate app configuration.

    Args:
        cnf (dict): Configurations subject to validation

    Raises:
        CnfError: Raised when there is a problem with the configuration.
    """
    if cnf["common"]["tmp_dirpath"] == "":
        raise CnfError("Configuration failed (tmp_dirpath is empty)")


def get_cli_cnf(args: list[str]) -> dict[str, Any]:
    """Parses command line arguments into a dictionary.

    Args:
        args (list[str]): Command line arguments

    Returns:
        dict[str, Any]: Configuration from CLI
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cnf_dirpath", help="Directory containing configuration files."
    )
    parser.add_argument("--tmp_dirpath", help="Directory to store temporary files.")
    parser.add_argument("--wrk_dirpath", help="Work directory.")
    parser.add_argument("--smtp_server", help="Email server to send notifications.")
    parser.add_argument("--smtp_localhost", help="Localhost for sending emails.")
    parser.add_argument(
        "--smtp_user", help="Username for authentication when sending emails."
    )
    parser.add_argument(
        "--smtp_password", help="Password for authentication when sending emails."
    )
    parser.add_argument("--from_addr", help="Email sender address.")
    parser.add_argument("--to_addr", help="Email recipient address.")

    mail_cfgs = (
        "smtp_server",
        "smtp_localhost",
        "smtp_user",
        "smtp_password",
        "from_addr",
        "to_addr",
    )
    result_common = {}
    result_mail = {}
    parsed_args = vars(parser.parse_args(args[1::]))

    for key, value in parsed_args.items():
        if key in mail_cfgs:
            result_mail[key] = value
        else:
            result_common[key] = value

    result = {}
    if len(result_common) > 0:
        result["common"] = result_common
    if len(result_mail) > 0:
        result["mail"] = result_mail

    return result


def init_app(app_cnf: dict) -> None:
    """Initialize application.

    Args:
        app_cnf (dict): Application configuration
    """
    # Make Temporary Directory
    pathlib.Path(os.path.expanduser(app_cnf["common"]["tmp_dirpath"])).mkdir(
        exist_ok=True
    )


def recursive_merge(
    target_dict: dict[str], source_dict: dict[str], overwrite_none: bool = False
) -> None:
    """Recursively merge source dict into target dict.

    Args:
        target_dict (dict[str]):\
            The target dictionary that will be modified and receive the merged result.
        source_dict (dict[str]):\
            The source dictionary whose values will be merged into the target dictionary.
        overwrite_none (bool):\
            Whether or not to overwrite with None when the source dictionary contains None.

    Note:
        This function has side effects and modifies the input dictionary "target_dict".
    """
    for key, value in source_dict.items():
        if (
            key in target_dict
            and isinstance(value, dict)
            and isinstance(target_dict[key], dict)
        ):
            recursive_merge(target_dict[key], source_dict[key])
        else:
            if not value is None or overwrite_none:
                target_dict[key] = value


class SMTPUserUnknown(smtplib.SMTPResponseException):
    def __init__(
        self, code: int, msg: bytes | str, err: dict[str, tuple[int, str]]
    ) -> None:
        """Initializer

        Args:
            code (int): Representative error code.
            msg (bytes | str): Representative message.
            err (dict[str, tuple[int, str]]): Email address that failed to send.
        """
        super().__init__(code, msg)
        self.err = err


class MailSender:
    """Class responsible for sending emails."""

    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        smtp_localhost: str,
        smtp_user: str,
        smtp_password: str,
        smtp_tls: bool,
        from_addr: str,
    ) -> None:
        """Initializer

        Args:
            smtp_server (str): SMTP server address.
            smtp_port (int): SMTP server port number.
            smtp_localhost (str): Local host name.
            smtp_user (str): SMTP server username.
            smtp_password (str): SMTP server password.
            smtp_tls (bool): Use TLS for SMTP.
            from_addr (str): Email sender address.
        """
        self._from_addr = from_addr
        self._smtp_server = smtp_server
        self._smtp_port = smtp_port
        self._smtp_localhost = smtp_localhost
        self._smtp_user = smtp_user
        self._smtp_password = smtp_password
        self._smtp_tls = smtp_tls

    def send_mail(
        self, to_addr: str, subject: str, message: str, attachments: list[str]
    ) -> None:
        """Send an email.

        Send an email with given details and attachments.

        Args:
            to_addr (str): Recipient's email address.
            subject (str): Subject of the email.
            message (str): Message body of the email.
            attachments (list[str]): List of zip file paths to attach to the email.
        """

        # メッセージの作成
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = self._from_addr
        msg["To"] = to_addr

        # テキスト部分の作成
        text = MIMEText(message)
        msg.attach(text)

        # 添付ファイルの作成
        for attachment in attachments:
            with open(attachment, "rb") as f:
                attachment_file = MIMEApplication(f.read(), _subtype="zip")
                attachment_file.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=os.path.basename(attachment),
                )
                msg.attach(attachment_file)

        # SMTPサーバーに接続してメールを送信する
        send_err = None
        if self._smtp_tls:
            with smtplib.SMTP_SSL(
                self._smtp_server, self._smtp_port, self._smtp_localhost
            ) as smtp:
                smtp.login(self._smtp_user, self._smtp_password)
                send_err = smtp.sendmail(self._from_addr, to_addr, msg.as_string())
        else:
            with smtplib.SMTP(
                self._smtp_server, self._smtp_port, self._smtp_localhost
            ) as smtp:
                smtp.login(self._smtp_user, self._smtp_password)
                send_err = smtp.sendmail(self._from_addr, to_addr, msg.as_string())

        if send_err:
            _, (first_code, first_msg) = next(iter(send_err.items()))
            raise SMTPUserUnknown(first_code, first_msg, send_err)


class CommandTimedOutException(Exception):
    """Custom exception raised when the command execution times out."""

    def __init__(self, command: str, output: str, *args: object):
        """Initializer.

        Args:
            command (str): The command that was being executed.
            output (str): The output of the command up to the point of timeout.
        """
        super().__init__(*args)
        self.command = command
        self.output = output


class KeywordTimedOutException(Exception):
    """Custom exception raised when waiting keyword times out in the command execution."""

    def __init__(self, command: str, output: str, keyword: str, *args: object):
        """Initializer.

        Args:
            command (str): The command that was being executed.
            output (str): The output of the command up to the point of timeout.
            keyword (str): The keyword that causes the command execution to time out.
        """
        super().__init__(*args)
        self.command = command
        self.output = output
        self.keyword = keyword


def run_command_with_timeout(
    command: list[str],
    overall_timeout: int,
    keyword: str = None,
    keyword_timeout: int = None,
    finalizer_func: Callable = None,
):
    """Executes a command and applies a timeout if a specific keyword is detected in the output.

    This function executes the given command and continuously monitors its output. If a specific keyword is detected,
    a timeout check is initiated immediately. If there is no new output following the keyword within the specified
    keyword_timeout, the command is terminated.

    Args:
        command (list[str]): The command to execute as a list of strings.
        overall_timeout (int): Maximum time in seconds to allow for the entire command execution.
        keyword (str): Keyword to watch for in the command's output.
        keyword_timeout (int): Time in seconds to wait for new output after detecting the keyword.
        finalizer_func (Callable, optional): A function to be called if the command exceeds the specified timeout. Default is None.

    Returns:
        str: The output of the command up to the point of completion or timeout.

    Raises:
        CommandTimedOutException: If the command times out after the overall timeout.
        KeywordTimedOutException: If the command times out after detecting the keyword.
    """
    if keyword_timeout is None:
        keyword = None

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    output = ""
    prev_line_contains_keyword = False
    timed_out = False
    due_to_keyword = False

    start_time = time.time()
    current_keyword: str = None

    while True:
        elapsed_time = time.time() - start_time

        remaining_time = overall_timeout - elapsed_time
        if remaining_time <= 0:
            _terminate_proc(process, finalizer_func=finalizer_func)
            timed_out = True
            due_to_keyword = False
            break
        elif prev_line_contains_keyword:
            # If this is the line after the line containing the keyword, use the keyword timeout.
            # If the overall timeout is shorter than the keyword timeout, use the overall timeout.
            if keyword_timeout < remaining_time:
                current_timeout = keyword_timeout
                due_to_keyword = True
            else:
                current_timeout = remaining_time
                due_to_keyword = False
        else:
            # If this is not the line after the line containing the keyword, use the overall timeout.
            current_timeout = remaining_time
            due_to_keyword = False

        if process.poll() is not None:
            break

        # Wait for the next line
        rlist, _, _ = select.select([process.stdout], [], [], current_timeout)

        if rlist:
            # If the next line is output
            line = process.stdout.readline()

            output += line
            print(line, end="")

            if keyword and keyword in line:
                current_keyword = keyword
                prev_line_contains_keyword = True
            else:
                prev_line_contains_keyword = False
        else:
            # If exited select.select due to timeout
            _terminate_proc(process, finalizer_func=finalizer_func)
            timed_out = True

    remaining_output, _ = process.communicate()

    output += remaining_output
    print(remaining_output)

    if timed_out:
        if due_to_keyword:
            raise KeywordTimedOutException(" ".join(command), output, current_keyword)
        else:
            raise CommandTimedOutException(" ".join(command), output)

    return output


def _terminate_proc(
    process: subprocess.Popen, wait_seconds: int = 120, finalizer_func: Callable = None
):
    """Terminates a subprocess.

    Sends a termination signal to the subprocess, and if it does not exit, forcefully terminates it.

    Args:
        process (subprocess.Popen): The target subprocess.
        wait_seconds (int, optional): The number of seconds to wait before forcefully terminating. Default is 120.
        finalizer_func (Callable, optional): A function to be called instead of sending a regular termination signal. Default is None.
    """
    if finalizer_func:
        finalizer_func()
    else:
        process.terminate()

    end_time = time.time() + wait_seconds
    while time.time() < end_time:
        if process.poll() is not None:
            break
        time.sleep(1)
    else:
        process.kill()
