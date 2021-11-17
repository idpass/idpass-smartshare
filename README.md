## Android Secure Communications Library

The **idpass-smartshare.aar** is an Android library that is used to securely share sensitive data. In the present design, it uses [Bluetooth](https://developers.google.com/nearby/connections/overview). The payload is encrypted with [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) in a 1-to-1 peer-to-peer communication.

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

The first app must call `getConnectionParamers`:

```java
String params = obj.getConnectionParamers();
obj.createConnection("dual", () -> {
    // a secure Bluetooth connection is created
    // anytime, the app may now call BluetoothApi.send
});
```

The second app must call `setConnectionParameters`:

```java
obj.setConnectionParameters(params);
obj.createConnection("dual", () -> {
    // a secure Bluetooth connection is created
    // anytime, the app may now call BluetoothApi.send
});

```

When a connection is created, either app can send a message by:

```java
obj.send(msg, () -> {
    // msg sent
});

```

The incoming messages, the transfer status of inbound/outbound messages, the connection-related events, and the debug log messages are handled in the callback functions specified in `init`. 

The mechanism to communicate the `params` connection code is up to the application. Such mechanism would include, but is not limited to, through a QR code.

## Open source dependencies

- [lazysodium-android](https://github.com/terl/lazysodium-android)
