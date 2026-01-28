# Centris

Centris 是用于识别开源组件的工具。
即使组件在复用时经历了代码或结构修改，Centris 也能进行精确且可扩展的识别。
原理与实验结果发表于第 43 届软件工程国际会议（ICSE'21）。

## 注意

**目前 CENTRIS 的专利由 [LABRADOR LABS](https://labradorlabs.ai/) 持有，因此禁止对该仓库及其源代码进行商业用途的使用。**

## 使用 Centris（Docker）

可在 zenodo 获取 Centris 的源码与数据集：

* [Source code](https://zenodo.org/record/4437945#.YB7nQ-gzaUk) (DOI: 10.5281/zenodo.4437945)
* [Dataset](https://zenodo.org/record/4514689#.YB7sN-gzaUk) (DOI: 10.5281/zenodo.4514689)

也可以使用 Docker 测试 Centris **[2022 年 10 月更新]**：

* [Centris Docker hub](https://hub.docker.com/repository/docker/seunghoonwoo/centris_code)

Docker 中使用 Centris：

```
$ sudo docker run -it seunghoonwoo/centris_code:latest
# cd /home/code
# python3 Detector.py "SOURCE_DIR_ROOT_PATH" "PACKAGE_NAME" 0 "linux"
```

* 将需要检测 OSS 组件的目标程序根目录填入 *"SOURCE_DIR_ROOT_PATH"*。
* 将程序名称（任意命名）填入 *"PACKAGE _NAME"*。
* 例如：

```
# git clone https://github.com/redis/redis   // 克隆 Redis 仓库用于测试
# python3 Detector.py "./redis/" "Redis" 0 "linux"
```

检测到的 OSS 组件列表会存放在 *"./res/PACKAGE_NAME"* 下。

*Centris 的原型（包含 2,000 个 OSS 项目）可在 IoTcube 上测试
([https://iotcube.net](https://iotcube.net)).*

## 使用 Centris（源码构建）

### 需求

#### 软件

* ***Linux***：Centris 设计上可运行于任意操作系统，但目前该仓库仅关注 Linux 环境。若进行少量环境配置（例如在 OSSCollector 中修改 ctags 解析器路径），也可在 Windows 上运行。
* ***Git***
* ***Python 3***
* ***[Universal-ctags](https://github.com/universal-ctags/ctags)***：用于函数解析。
* ***[Python3-tlsh](https://pypi.org/project/python-tlsh/)***：用于函数哈希。

Python3-tlsh 安装方法：

```
sudo apt-get install python3-pip
sudo pip3 install py-tlsh
```

我们使用的版本：Ubuntu 18.04 上的 Python 3.9.1、python3-tlsh 4.5.0、universal-ctags p5.9.20201227.0。

#### 硬件

* 为了识别大量 OSS 数据集，建议至少 32 GB 内存。

### 运行 Centris

如果路径相关问题较多，建议使用绝对路径进行测试。

#### OSSCollector（src/osscollector/）

1. 将需要 git clone 的 URL（会包含在组件库中）收集到一个文件中，参考 [sample](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/osscollector/sample) 文件。
2. 在 [OSS_Collector.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/osscollector/OSS_Collector.py) 中指定目录路径（第 17 至 21 行），用于存放克隆的仓库及其函数。同时在此处指定已安装的 ctags 路径。
3. 执行 [OSS_Collector.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/osscollector/OSS_Collector.py)

```
python3 OSS_Collector.py
```

（可能因编码问题出现若干警告。）

4. 查看输出（以下为默认路径说明）。

* ***./osscollector/repo_src/***：存放已收集仓库的源码；
* ***./osscollector/repo_date/***：存放各仓库各版本的发布时间；
* ***./osscollector/repo_functions/***：存放从各仓库提取的函数。

#### Preprocessor（src/preprocessor/）

* 预处理生成组件库有两种方式：使用完整版本的
  preprocessor（[Preprocessor_full.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_full.py)，论文中使用）
  或精简版本
  preprocessor（[Preprocessor_lite.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_lite.py)）。
  二者区别在于：完整版本会包含两个软件共有函数中的相似函数，而精简版本仅考虑完全相同的函数。使用精简版本构建组件库耗时更短，但组件识别准确率会略有下降。

1. 在 [Preprocessor_full.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_full.py)
   或 [Preprocessor_lite.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_lite.py) 中设置合适的目录路径（与上面 OSSCollector 第 2 步一致）。

2. 执行对应的 Python 脚本（[Preprocessor_full.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_full.py)
   或 [Preprocessor_lite.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_lite.py)）。

```
python3 Preprocessor_full.py
```

or

```
python3 Preprocessor_lite.py
```

3. 查看输出（以下为默认路径说明）。

* ***./preprocessor/componentDB/***：构建的组件库目录；
* ***./preprocessor/verIDX/***：存放各 OSS 的索引信息；
* ***./preprocessor/metaInfos/***：存放各 OSS 的元信息；
* ***./preprocessor/weights/***：存放各 OSS 中各函数的权重（用于预测识别出的组件所使用的版本）；
* ***./preprocessor/funcDate/***：存放各 OSS 中各函数的出生日期；

#### Detector（src/detector/）

1. 在 [Detector.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/detector/Detector.py) 中指定组件库路径与结果保存目录。

2. 运行 [Detector.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/detector/Detector.py)，传入目标软件的根路径，用于识别其组件。

```
python3 Detector.py /path/of/the/target/software
```

3. 查看组件识别结果（默认输出路径：./detector/res/）

### 复现论文结果

由于若干原因（包括 Centris 的商业使用限制与数据集规模巨大），我们发布的组件库只能用于识别 OSS 组件列表（不含版本信息）。

因此，复现论文结果有两种方式：

1. 从组件库构建到组件识别，执行全部三个模块；
2. 使用我们提供的数据集。

#### 情况 1：执行全部三个模块

1. 收集 10,000+ 个 Git 仓库用于创建组件库。论文中收集了截至 2020 年 4 月、GitHub 星标超过 100 的 C/C++ 仓库。该过程视仓库数量可能耗时数天至数周。

2. 使用 [Preprocessor_full.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/preprocessor/Preprocessor_full.py) 创建组件库。

3. 执行 [Detector.py](https://github.com/WOOSEUNGHOON/Centris-public/blob/main/src/detector/Detector.py)。

4. 查看结果。

#### 情况 2：使用提供的数据集

数据集：从 [zenodo](https://zenodo.org/record/4514689#.YB7sN-gzaUk) 下载（5 GB）。

1. 解压下载的文件（Centris_dataset.tar）。

2. 安装 Ctags 与 python-tlsh（见“需求”）。在 "Detector_for_OSSList.py" 文件（第 22 行）中指定 ctags 路径。

3. 有四个示例目标软件（ArangoDB、Crown、Cocos2dx、Splayer），用于论文中的深入对比。

+ [2a] 若要检查这四个示例软件的检测结果，将 "Detector_for_OSSList.py" 第 193 行的 "testmode" 设置为 1，并调整第 196 与 197 行的文件路径。
+ [2b] 若要检查其他软件的检测结果，将 "Detector_for_OSSList.py" 第 193 行的 "testmode" 设置为 0。

4. Execute the "Detector_for_OSSList.py".

[2a]

```
python3 Detector_for_OSSList.py
```

[2b]

```
python3 Detector_for_OSSList.py /path/of/the/target/software
```

5. 查看结果（默认输出路径：./res/.）

### 关于

本仓库由 Seunghoon Woo 编写与维护。

如需报告问题，可在 [GitHub 仓库](https://github.com/WOOSEUNGHOON/Centris-public) 提交 issue，或发送邮件至（<seunghoonwoo@korea.ac.kr>）。
