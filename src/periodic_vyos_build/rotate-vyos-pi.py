#!/usr/bin/python3
import os
import re
import sys
from logging import (
    error,
    getLogger,
)
from logging.config import dictConfig

import periodic_vyos_build_lib as lib


class Main:
    def __init__(self, args: list[str]) -> None:
        """Initializer

        Args:
            args (list[str]): List of command line arguments.
        """
        # コマンドライン引数をパース
        cli_cnf = lib.get_cli_cnf(args)

        # ConfigurationLoader を準備
        cnf_loader = lib.ConfigurationLoader(cli_cnf["common"]["cnf_dirpath"])

        # アプリケーション設定を得る
        try:
            self._app_cnf = cnf_loader.get_app_cnf(cli_cnf)
        except lib.CnfError as cnf_error:
            # この時点ではまだロギングの設定が終わっていないので、root の ERROR として出力する。
            error(str(cnf_error))
            raise cnf_error

        # ロギング設定を得る
        log_cnf = cnf_loader.get_log_cnf(self._app_cnf)

        # ロギング設定を行う
        dictConfig(log_cnf)
        self._logger = getLogger(__name__)

        # アプリケーションを初期化 (tmp ディレクトリを作成する、など)
        lib.init_app(self._app_cnf)

        self._pub_dirpath = os.path.expanduser(self._app_cnf["common"]["pub_dirpath"])
        self._rotate = self._app_cnf["rotate"]["image"]

    def execute(self):
        os.chdir(self._pub_dirpath)
        files = [
            f
            for f in os.listdir(self._pub_dirpath)
            if os.path.isfile(os.path.join(self._pub_dirpath, f))
        ]

        file_re = re.compile(
            "(.*\\.)[0-9]{4}-[0-9]{2}-[0-9]{2}(\\.zip)",
        )

        target_file_dict: dict[str, list[str]] = {}

        for file in files:
            re_result = file_re.match(file)
            if re_result:
                key_name = f"{re_result.group(1)}yyyy-MM-dd{re_result.group(2)}"

                if not key_name in target_file_dict:
                    target_file_dict[key_name] = []

                target_file_dict[key_name].append(file)

        self._logger.info(f"Rotation target is {target_file_dict}")

        for value in target_file_dict.values():
            value.sort()
            del_count = max(len(value) - self._rotate, 0)
            while del_count > 0:
                del_item = value.pop(0)
                os.remove(del_item)
                self._logger.info(f"Delete {del_item}.")
                del_count = del_count - 1


if __name__ == "__main__":
    main_obj = Main(sys.argv)
    sys.exit(main_obj.execute())
