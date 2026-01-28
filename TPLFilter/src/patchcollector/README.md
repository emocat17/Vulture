## PatchCollector

该工具用于从 GitHub 提交中收集与特定 CVE 相关的安全补丁，这些 CVE 针对的是开源项目（托管在 GitHub 上）。



#### 环境

环境文件为 `environment.yml`，可通过以下命令创建 conda 环境：

 `conda evn create -f environment.yml`。



#### 设置

该工具依赖 GitHub API 与 NVD API，并使用 OpenAI API 进行分析。对应需要以下 API key，建议添加为环境变量。

* ``GITHUB_API_KEY = "your_github_access_api_key"``
* ``NVD_API_KEY = "your_nvd_access_api_key"``
* ``OPENAI_API_KEY = "your_openai_api_key"``



#### 安全补丁收集

在 `collect_patch.py` 中设置特定 CVE 的参数，然后运行 `collect_patch.py`

例如（`CVE-2016-7178`）：

```python
# set target CVE info

str_vendor = "wireshark"
str_product = "wireshark"
tuple_version = ("wireshark-2.0.5", "wireshark-2.0.6")
str_cve_description = "epan/dissectors/packet-umts_fp.c in the UMTS FP dissector in Wireshark 2.x before 2.0.6 does not ensure that memory is allocated for certain data structures, which allows remote attackers to cause a denial of service (invalid write access and application crash) via a crafted packe"
```
