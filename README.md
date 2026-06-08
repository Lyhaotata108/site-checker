# 网站批量状态检测工具

粘贴域名列表，一键检测网站是否可访问、状态码、响应时间。

## 部署到 Vercel（3步）

### 第一步：上传到 GitHub

1. 打开 https://github.com/new 新建一个仓库（比如叫 `site-checker`）
2. 把这三个文件上传上去：
   - `index.html`
   - `api/check.py`
   - `vercel.json`

### 第二步：导入到 Vercel

1. 打开 https://vercel.com，用 GitHub 账号登录
2. 点击 **Add New Project**
3. 选择刚才创建的 `site-checker` 仓库
4. 直接点 **Deploy**，不需要改任何配置

### 第三步：完成

部署完成后 Vercel 会给你一个网址，比如：
`https://site-checker-xxx.vercel.app`

打开就能用，以后每次 push 到 GitHub 自动更新。

## 文件说明

```
index.html      前端页面
api/check.py    后端检测函数（Vercel Serverless）
vercel.json     Vercel 配置
```

## 注意

- 每次最多检测 100 个域名（Vercel 函数有 30 秒时间限制）
- 免费版 Vercel 完全够用
