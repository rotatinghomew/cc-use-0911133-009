# vulnerable_transfer_planner

演练家庭转移资料处理：家庭需求、暴露、护送能力、车辆和任务回执。当前入口是 `vulnerable_transfer_planner.fieldwork.command`，它使用本地 JSON 资料和 SQLite 状态；目录 `vulnerable_transfer_planner` 存放业务模块，`tests/transfer_missions` 验证既有业务行为。

## 环境

使用 Python 3.11，全部依赖来自标准库。`requirements.txt` 为空，不需要下载数据、模型或第三方包。数据库在运行时创建，可以删除临时数据库重新开始。

## 检查

```bash
python3 -m unittest discover -s tests/transfer_missions -v
python3 -m unittest discover -s tests/analysis_context -v
python3 -m compileall -q vulnerable_transfer_planner tests scripts
```

## 运行

```bash
python3 -m vulnerable_transfer_planner.fieldwork.command  fixtures/demo.json --database /tmp/vulnerable_transfer_planner-demo.sqlite3
python3 scripts/check_project.py
```

`check_project.py` 串行执行测试、编译和真实业务入口，将本次业务输出完整打印到终端；状态文件使用独立临时目录，重复运行不沿用上次状态。

批量分析资料位于 `fixtures/household_linkage.json`，字段含义见 `docs/data.md`。它与当前单笔流程的输入格式不同，不能直接交给原来的入口处理。

## 名册同户分析（只读建议）

```bash
python3 -m vulnerable_transfer_planner.linkage fixtures/household_linkage.json --output /tmp/household-linkage
```

该入口由 `vulnerable_transfer_planner.linkage` 子包实现，与单笔任务流程完全隔离：不连接 SQLite、不导入任务状态机，因此任何分析建议都不会改变现有任务状态，也不会改写或合并原始 `registration_id`。它输出候选关系与证据、不能自动裁定的冲突、不同合理链接下的需求范围（待转移人数与车型缺口）以及按信息价值排序的复核优先级。

人工复核结论可通过 `--decisions` 局部叠加，只重算受影响群组并保留全部来源（含被覆盖的历史结论）：

```bash
python3 -m vulnerable_transfer_planner.linkage fixtures/household_linkage.json \
    --output /tmp/household-linkage --decisions decisions.json
```

分析原则与边界见 `docs/linkage.md`，对应测试在 `tests/analysis_context/test_linkage.py`。
