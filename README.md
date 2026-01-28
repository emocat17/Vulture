## VULTURE

VULTURE 旨在检测由存在漏洞的第三方库（TPL）复用所导致的 1-day 漏洞。 
我们的论文 **Enhancing Security in Third-Party Library Reuse - Comprehensive Detection of 1-day Vulnerabilitythrough Code Patch Analysis** 已被 NDSS'25 录用！

**数据集**地址：https://zenodo.org/records/13824990

它由三个模块组成：***TPLFILTER Construction*、*TPL Reuse Identification* 和 *1-day Vulnerability Detection***。每个模块都在同名目录中实现。

![](vulture.png)



#### 环境

pip 环境依赖在 `requirments.txt` 中提供，可以运行以下命令：

 `pip install -r requirements.txt`。

还需要以下工具：

```
sudo apt install clang-format
```

并在[此处](https://github.com/universal-ctags/ctags)安装 *ctags*。

#### 步骤

##### TPLFilter 构建

TPL 构建基于 [Centris](https://github.com/WOOSEUNGHOON/Centris-public?tab=readme-ov-file#software) 开发。你可以选择目标平台，并使用 TPLFilter 构建包含 TPL 函数哈希、版本、相关 CVE 以及对应补丁的数据库。本示例聚焦于 IoT 平台。

###### 收集与目标平台相关的关键词列表并排除不需要的仓库：

1. 你可以先按指定语言收集 GitHub 上的仓库：

   ```shell
   cd TPLselection
   python3 git_all_spider.py C cpp --stars 100 500
   ```

   **Languages**：用参数指定目标语言。上面示例使用 `C` 和 `cpp`。
   **Star Range**：用 `--stars` 后跟两个数字设置要收集的仓库星标范围。示例中目标为 100 到 500 星的仓库。
2. 然后通过关键词匹配过滤并排除不需要的 TPL，关键词示例在 `TPLFilter/src/TPLselection/keywordsList` 中



###### 收集 TPL 并生成代码哈希

1. 将上面收集的 URL 放入 `TPLFilter/src/osscollector/targetTPLs`
2. `cd ../osscollector` 并运行 `python3 OSS_Collector.py` 收集 TPL。可单进程或多进程运行。
3. 然后 `cd ../preprocessor` 运行 `python3 Preprocessor.py` 进行冗余消除。



###### 漏洞与补丁收集

更多信息请参见[这里](TPLFilter/src/patchcollector/README.md)。

示例在[这里](TPLFilter/src/patchcollector/example.pdf)。

你可以将它们放入 `OneDayDetector` 的 aligned_patch 与 aligned_cpe 目录。
##### TPL 复用检测

1. 现在可以 `cd ../TPLReuseDetector` 并运行 `python3 Detector.py /path/of/the/target/software`（注意路径末尾不要加“/”）。复用的 TPL 及其版本可在 `res/result_your_software_name` 中找到
2. 然后运行 `python3 fp_eliminator.py res/result_your_software_name_func` 去除误报。最终结果在 `modified_result_without_funcyour_software_name` 中



##### 1-day 漏洞检测

进入 `OneDayDetector` 目录运行 `python3 VersionBasedDetection.py /path/of/the/target/software`，即可直接得到结果。

结果会显示哪些 CVE 可能影响你的软件，以及你已修复的内容，如下所示：

```
Vulnerable CVEs Exact: set('freetype_freetype/CVE-2014-9666')
Vulnerable CVEs Modified: set('curl_curl/CVE-2023-28322')
Patched CVEs Exact: set('freetype_freetype/CVE-2014-9660')
Patched CVEs Modified: set('curl_curl/CVE-2022-27781')
Version Detection: set('curl_curl/CVE-2016-0754', 'freetype_freetype/CVE-2017-8287', 'mbed-tls_mbedtls/CVE-2020-36477', 'freetype_freetype/CVE-2010-3311')
```


