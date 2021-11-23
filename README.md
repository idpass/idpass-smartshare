## Android Secure Communications Library

The **idpass-smartshare.aar** is an Android library that is used to securely share sensitive data. In the present design, it uses [Bluetooth](https://developers.google.com/nearby/connections/overview). The payload is encrypted with [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) in a 1-to-1 peer-to-peer communication. 

The first app generates a per session connection code in `params`. The second app acquires this `params` connection code. Such exchange of the `params` connection code can be done, but is not limited to, through the use of a QR code. The connection code securely identifies the other peer and its public key used to encrypt the payload. This connection code are ephemeral and is regenerated per session in both ends. 

## Usage

The app must initialized with `init`:

```java
String msg = "Hello, World!";
BluetoothSecure obj = new BluetoothSecure();
obj.init(getCurrentActivity(),
    (log) -> {
        System.out.println(log);
    }, 
    (msg) -> {
        System.out.println(msg);
    }
);
```

The first app must call [getConnectionParameters](https://github.com/idpass/react-native-idpass-smartshare/blob/main/example/src/App.tsx#L144-L166):

```java
String params = obj.getConnectionParameters();

// Let `params` be known to the other peer, for example, visually through
// the use of a QR code generator

obj.createConnection("dual", () -> {
    // a secure Bluetooth connection is created
    // anytime, the app may now call BluetoothApi.send
});
```

The second app must call [setConnectionParameters](https://github.com/idpass/react-native-idpass-smartshare/blob/main/example/src/App.tsx#L191-L201):

```java
// Get the `params` connection code. For example, visually through
// the use of a QR code scanner

obj.setConnectionParameters(params);
obj.createConnection("dual", () -> {
    // a secure Bluetooth connection is created
    // anytime, the app may now call BluetoothApi.send
});

```



When a connection is created, either app can [send](https://github.com/idpass/react-native-idpass-smartshare/blob/main/example/src/App.tsx#L231-L237) a message by:

```java
obj.send(msg, () -> {
    // msg sent
});

```

The incoming messages, the transfer status of inbound/outbound messages, the connection-related events, and the debug log messages are handled in the callback functions specified in `init`. The [example](https://github.com/idpass/react-native-idpass-smartshare/blob/main/example/src/App.tsx#L82-L109) test application shows the handling of these events. 

The mechanism to communicate the `params` connection code is up to the application. Such mechanism would include, but is not limited to, through a QR code.

## Open source dependencies

- [lazysodium-android](https://github.com/terl/lazysodium-android)
