from scipy.optimize import minimize

# number of produce items user is buying
n = 2
# price of produce items
A = [5, 9]

# number of credit types
m = 3
# amount of credit types in user's wallet
C = [4, 5, 6]

print 'Buying items: ' + str(A)
print 'Wallet contents: ' + str(C)

def f(x):
    f = 0
    for i in xrange(n):
        s = 0
        for j in xrange(m):
            s += x[i*m + j]
        f += (A[i] - s)
    return f

cons = []
for i in xrange(n):
    cons.append({'type': 'ineq', 'fun': lambda x, i=i: A[i] - sum(x[i*m : (i+1)*m])})

for j in xrange(m):
    cons.append({'type': 'ineq', 'fun': lambda x, j=j: C[j] - sum(x[j : n*m : m])})

bnds = []
x0 = []
for i in xrange(n):
    for j in xrange(m):
        bnds.append((0, C[j]))
        x0.append(0)

res = minimize(f, x0, method='SLSQP', bounds=bnds, constraints=cons)
print res

for i in xrange(n):
    print 'Would pay for item ' + str(i) + ': ' + str(sum(res['x'][i*m : (i+1)*m]))
