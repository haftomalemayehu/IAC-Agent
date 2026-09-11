package com.iacagent.iacagent.approval.jdbc;

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
 * Test-only DataSource wrapper that injects a failure at a precisely chosen point inside a
 * transaction, so a test can prove real transactional rollback rather than merely asserting the
 * happy path. Delegates everything except optionally throwing on a chosen
 * {@code PreparedStatement#executeUpdate()} call number, or on {@code Connection#commit()}.
 */
final class FaultInjectingDataSource implements DataSource {

    private final DataSource delegate;
    private final IntPredicate failOnExecuteUpdateCallNumber;
    private final boolean failOnCommit;
    private int executeUpdateCallCount = 0;

    static FaultInjectingDataSource throwingOnExecuteUpdateCall(DataSource delegate, int callNumberToFailOn) {
        return new FaultInjectingDataSource(delegate, n -> n == callNumberToFailOn, false);
    }

    static FaultInjectingDataSource throwingOnCommit(DataSource delegate) {
        return new FaultInjectingDataSource(delegate, n -> false, true);
    }

    private FaultInjectingDataSource(DataSource delegate, IntPredicate failOnExecuteUpdateCallNumber, boolean failOnCommit) {
        this.delegate = delegate;
        this.failOnExecuteUpdateCallNumber = failOnExecuteUpdateCallNumber;
        this.failOnCommit = failOnCommit;
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
                    if (failOnCommit && "commit".equals(method.getName())) {
                        throw new SQLException("simulated commit failure (fault injection)");
                    }
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
                        executeUpdateCallCount++;
                        if (failOnExecuteUpdateCallNumber.test(executeUpdateCallCount)) {
                            throw new SQLException("simulated executeUpdate failure on call " + executeUpdateCallCount + " (fault injection)");
                        }
                    }
                    return invokeReal(real, method, args);
                });
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
