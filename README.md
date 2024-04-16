# threat-demo

威胁情报平台demo

## local_translate本地翻译环境
依赖opus-mt-en-zh翻译模型

下载地址：https://huggingface.co/Helsinki-NLP/opus-mt-en-zh

工程放置在/local_translate/

调用端口8398

## threat-demo威胁情报平台

ReturnPageController
页面：/

SendMessageController
页面调用api:
- /say 展示资讯内容 参数：point 评分 page 页面 past 过去X天
- /query 查询资讯页数 参数：point 评分 past 过去X天
- /trans 翻译接口 参数：trans 翻译内容

DataPlanController
任务api（页面也可以调用）：
- /ins 获取最新资讯
- /transall 翻译全部资讯

项目Service构成：

服务调用
- GetDataSourceService 数据源读取和管理*
- GetDataFeedService 数据爬虫执行
- ResolveGetInfoService 数据后处理
- SaveNewInfoService 数据入库和管理

静态调用
- GetInfoFilterService 入库筛选和查询筛选
- SetNetworkService 网络配置
- GetDjangoService django调用




