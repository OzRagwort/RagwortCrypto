# RagwortCrypto

## RagwortCrypto?
제가 국가 암호 공모전에 참여하며 암호를 사용하기 위해 JCE를 사용하기도 하고 직접 구현해보기도 했습니다. 프로그래밍에 암호를 사용하면서 느낀 점은 '이거 암호 처음 쓰는 사람한테는 어렵겠다' 였습니다. 지도 교수님께서도 자신이 암호학 수업 때 암호를 사용하여 프로그램을 만들어 보라는 과제를 낸적이 있는데 사용 방법이 너무 어렵고 헷갈려 대부분이 포기했다는 것입니다. 특히 국산암호는 자료가 없어 더욱 힘이 들다는 것이었습니다. 알면 사용하기 쉬울수 있어도 처음 사용하는 사람에게는 어려울 수 있겠다. __누구나 쉽고 간단하게 사용할 수 있는 JAVA 라이브러리__ 를 개발하고 싶다. 그것이 바로 제가 RagwortCrypto를 만든 계기가 되었습니다. 


## 사용 가능한 알고리즘
* 암호화 알고리즘 : 
```
AES(128, 192, 256) - ECB, CBC, CTR
Triple DES(64, 128) - ECB, CBC, CTR
ARIA(128, 192, 256) - ECB
LEA(128, 192, 256) - ECB, CBC, CTR
HIGHT(64) - ECB
SEED(128) - ECB
```
* 해시함수 알고리즘 : 
```
SHA(SHA-1, SHA-2)
MD5
LSH(256, 512)
```

## 사용 방법 & 참고할것

### 클래스 호출
* 암호 알고리즘
```
import cryp.sym.*;
import cryp.sym.AES;
```
* 해시함수 알고리즘
```
import cryp.hash.*;
import cryp.hash.SHA;
```
### 객체 생성
```
AES aes = new AES();
SHA sha = new SHA();
```
### 암·복호화
* ECB 모드
```
cipher = aes.enc(plain, key);
plain = aes.dec(cipher, key);
```
* CBC, CTR 모드
```
cipher = aes.enc(plain, key, "CBC", iv);
plain = aes.dec(cipher, key, "CBC", iv);
```
* 해시함수
```
- byte[] 형
byte[] plain = { ... };
결과값 저장 변수 = sha.sha1(plain);
- String 형
String plain = "hello";
결과값 저장 변수 = sha.sha1(plain);
```
byte[] 형이 들어가면 byte[]형이 리턴되고 String형이 들어가면 String형이 리턴됩니다 !

### 각종 변수들
* 키 설정
```
byte[] key = new byte[16]; -> 128bit 키
byte[] key = new byte[24]; -> 192bit 키
byte[] key = new byte[32]; -> 256bit 키
```
##### Triple DES
```
트리플 데스의 특성상 3개의 키가 필요 !
byte[] key_des = {
(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,	//첫번째 키
(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,	//두번째 키
(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f	//세번째 키
}; //Triple DES에서 사용될 키 3개
```

### 사용 예시
https://github.com/OzRagwort/RagwortCrypto/blob/master/com/main/cryp_test.java


## 개발한 사람

장원영 : qmamzm0123@naver.com

