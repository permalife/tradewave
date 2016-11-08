from scipy.optimize import minimize

# number of produce items user is buying
n = 2
# prices of produce items
A = [5, 19]

# number of credit types
m = 3
# amount of credit types in user's wallet
C = [4, 5, 10]

# specify which credits can buy which items
# each row corresponds to a credit type
# 1 means can buy item at index i, 0 means can not
D = [[1, 0], [0, 1], [1, 1]]

print 'Buying items: ' + str(A)
print 'Wallet contents: ' + str(C)

for i in xrange(m):
    print 'Credit ' + str(i) + ' can buy: ' + str(D[i])

# main cost function
def f(x):
    f = 0
    for i in xrange(n):
        s = sum(x[i*m : (i+1)*m])
        f += (A[i] - s)
    return f

# define the constraints
cons = []

# try to pay requested amount for each item
for i in xrange(n):
    cons.append({'type': 'ineq', 'fun': lambda x, i=i: A[i] - sum(x[i*m : (i+1)*m])})

# can not exceed the amount of credit held for each credit type
for j in xrange(m):
    cons.append({'type': 'ineq', 'fun': lambda x, j=j: C[j] - sum(x[j : n*m : m])})

# define bounds and the initial guess
bnds = []
x0 = []
for i in xrange(n):
    for j in xrange(m):
        upper = 0
        if D[j][i]:
            upper = C[j]
        bnds.append((0, upper))
        x0.append(0)

# run the algorithm
res = minimize(f, x0, method='SLSQP', bounds=bnds, constraints=cons)
print res

for i in xrange(n):
    print 'Would pay for item ' + str(i) + ': ' + str(sum(res['x'][i*m : (i+1)*m]))
