## LiteOS 目标漏洞检测（OneDayDetector）

```bash
conda activate vulture
cd /home/Gitworks/Vulture/OneDayDetector
python VersionBasedDetection.py /home/Gitworks/Vulture/OneDayDetector/target/LiteOS
```

## 任意仓库完整流程（检测 TPL 复用 + 1-day 漏洞检测）

```bash
conda activate vulture
cd /home/Gitworks/Vulture/TPLReuseDetector
python Detector.py /path/to/repo
python fp_eliminator.py res/result_<repoName>_func

cd /home/Gitworks/Vulture/OneDayDetector
python VersionBasedDetection.py /path/to/repo
```

## NanoLog 示例

```bash
conda activate vulture
cd /home/Gitworks/Vulture/TPLReuseDetector
python Detector.py /home/Gitworks/Vulture/OneDayDetector/target/NanoLog-master
python fp_eliminator.py res/result_NanoLog-master_func

cd /home/Gitworks/Vulture/OneDayDetector
python VersionBasedDetection.py /home/Gitworks/Vulture/OneDayDetector/target/NanoLog-master
```
