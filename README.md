# GoogleAuth

google authenticator两步验证golang实现

## 添加引用

```shell
go get 
```




## 使用
### 获取base32后的秘钥

```go

 //strSize:随机的源字符串长度
 //RandType:随机源字符串类型:RandTypeAlphaNum=数字&字符 , RandTypeAlpha = 字母 , RandTypeNum=仅数字 
 secretKey := googleauth.RandSecret(16,googleauth.RandTypeAlphaNum)

```


### 基于秘钥获取Code

```go
code,_ := googleauth.GetCode(secretKey)
fmt.Println("code:",code)
```

### 秘钥生成二维码

```go
img,_ :=googleauth.QrCode(secretKey,"jmol","jmolboy",200)
	
```


### 秘钥生成base64图片

```go
base64Img,_ :=googleauth.QrBase64(secretKey,"jmol","jmolboy",200)
fmt.Print("base64:"+base64Img)
```