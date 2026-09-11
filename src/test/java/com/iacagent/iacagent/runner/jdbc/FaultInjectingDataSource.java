package com.iacagent.iacagent.runner.jdbc;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.function.IntPredicate;
import java.util.logging.Logger;

/**
 * Test-only DataSource wrapper that injects a failure at a precisely chosen point, so a test can
 * prove real fail-closed behavior rather than merely asserting the happy path. Mirrors
 * {@code com.iacagent.iacagent.approval.jdbc.FaultInjectingDataSource} exactly - kept as a separate,
 * package-scoped copy rather than a shared cross-subsystem utility, consistent with how each JDBC
 * subsystem's tests are otherwise self-contained in this codebase.
 */
final class FaultInjectingDataSource implements DataSource {

    private final DataSource delegate;
    private final IntPredicate failOnExecuteUpdateCallNumber;

    static FaultInjectingDataSource throwingOnExecuteUpdateCall(DataSource delegate, int callNumberToFailOn) {
        return new FaultInjectingDataSource(delegate, n -> n == callNumberToFailOn);
    }

    private FaultInjectingDataSource(DataSource delegate, IntPredicate failOnExecuteUpdateCallNumber) {
        this.delegate = delegate;
        this.failOnExecuteUpdateCallNumber = failOnExecuteUpdateCallNumber;
    }

    @Override
    public Connection getConnection() throws SQLException {
        return wrapConnection(delegate.getConnection());
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        return wrapConnection(delegate.getConnection(username, password));
    }

    private Connection wrapConnection(Connection real) {
        return (Connection) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{Connection.class},
                (proxy, method, args) -> {
                    if ("prepareStatement".equals(method.getName())) {
                        PreparedStatement realStatement = (PreparedStatement) invokeReal(real, method, args);
                        return wrapStatement(realStatement);
                    }
                    return invokeReal(real, method, args);
                });
    }

    private Object wrapStatement(PreparedStatement real) {
        return Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{PreparedStatement.class},
                (proxy, method, args) -> {
                    if ("executeUpdate".equals(method.getName())) {
                        int callNumber = incrementAndGetCallCount();
                        if (failOnExecuteUpdateCallNumber.test(callNumber)) {
                            throw new SQLException("simulated executeUpdate failure on call " + callNumber + " (fault injection)");
                        }
                    }
                    return invokeReal(real, method, args);
                });
    }

    private int executeUpdateCallCount = 0;

    private synchronized int incrementAndGetCallCount() {
        return ++executeUpdateCallCount;
    }

    private static Object invokeReal(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
        return delegate.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
        delegate.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
        delegate.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
        return delegate.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() {
        return Logger.getLogger("global");
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        return delegate.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        return delegate.isWrapperFor(iface);
    }
}
