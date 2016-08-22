'use strict';

window.app = angular.module('FullstackGeneratedApp', ['fsaPreBuilt', 'ui.router', 'ui.bootstrap', 'ngAnimate']);

app.config(function ($urlRouterProvider, $locationProvider) {
  // This turns off hashbang urls (/#about) and changes it to something normal (/about)
  $locationProvider.html5Mode(true);
  // If we go to a URL that ui-router doesn't have registered, go to the "/" url.
  $urlRouterProvider.otherwise('/');
  // Trigger page refresh when accessing an OAuth route
  $urlRouterProvider.when('/auth/:provider', function () {
    window.location.reload();
  });
});

// This app.run is for controlling access to specific states.
app.run(function ($rootScope, AuthService, $state) {

  // The given state requires an authenticated user.
  var destinationStateRequiresAuth = function destinationStateRequiresAuth(state) {
    return state.data && state.data.authenticate;
  };

  // $stateChangeStart is an event fired
  // whenever the process of changing a state begins.
  $rootScope.$on('$stateChangeStart', function (event, toState, toParams) {

    if (!destinationStateRequiresAuth(toState)) {
      // The destination state does not require authentication
      // Short circuit with return.
      return;
    }

    if (AuthService.isAuthenticated()) {
      // The user is authenticated.
      // Short circuit with return.
      return;
    }

    // Cancel navigating to new state.
    event.preventDefault();

    AuthService.getLoggedInUser().then(function (user) {
      // If a user is retrieved, then renavigate to the destination
      // (the second time, AuthService.isAuthenticated() will work)
      // otherwise, if no user is logged in, go to "login" state.
      if (user) {
        $state.go(toState.name, toParams);
      } else {
        $state.go('login');
      }
    });
  });
});

'use strict';

app.controller('CheckoutCtrl', function ($scope, cartItems, AuthService, Card, Cart, Order, me, $rootScope, Address) {

  $scope.cartItems = cartItems;
  $scope.me = me;

  if ($scope.me) Card.getMyCards().then(function (cards) {
    $rootScope.cards = cards;
  });else $rootScope.cards = [];

  if ($scope.me) Address.getMyAddresses().then(function (addresses) {
    $rootScope.addresses = addresses;
  });else $rootScope.addresses = [];

  $scope.newOrder = {
    orderSummary: {
      priceTotal: cartItems.reduce(function (sum, item) {
        return Math.round(sum + item.product.price * item.quantity);
      }, 0)
    },
    orderDetails: {
      items: $scope.cartItems
    }
  };

  function responseHandler(status, response) {
    if (response.error) {
      console.error(response.error.message);
    } else {
      var chargeDetails = {};
      chargeDetails.source = response.id;
      chargeDetails.stripeToken = response.id;
      chargeDetails.userId = $scope.user.id;
      chargeDetails.amount = $scope.newOrder.orderSummary.priceTotal;

      Order.sendToStripe(chargeDetails).then(function () {
        return Order.createOrderSummary(order.orderSummary);
      }).then(function (orderSummary) {
        order.orderDetails.orderSummaryId = orderSummary.id;
        order.orderDetails.items.forEach(function (item) {
          item.purchaseCost = item.product.price * item.quantity;
        });
        return Order.createOrderDetails(order.orderDetails);
      }).then(function () {

        $scope.cartItems = {};
        if (user) {
          Cart.clearCartUser();
        } else {
          Cart.clearCartVisitor();
        }
      });
    }
  }

  $scope.createOrder = function (order) {
    order.orderSummary.cardId = order.card.id;

    var $form = {
      'number': order.card.number,
      'exp_month': order.card.exp_month,
      'exp_year': order.card.exp_year,
      'cvc': order.card.cvc
    };

    AuthService.getLoggedInUser().then(function (userLoggedIn) {
      $scope.user = userLoggedIn;
      return Stripe.card.createToken($form, responseHandler);
    }).catch(console.log.bind(console));
  };
});

'use strict';

app.config(function ($stateProvider) {
  $stateProvider.state('checkout', {
    url: '/checkout',
    templateUrl: 'js/checkout/checkout.html',
    controller: 'CheckoutCtrl',
    resolve: {
      cartItems: function cartItems(Cart, AuthService) {
        return AuthService.getLoggedInUser().then(function (user) {
          if (user) return Cart.fetchCartItems();else return Cart.fetchNotLoggedInItems();
        }).then(function (cartItems) {
          return cartItems.map(function (cartItem) {
            cartItem.product.price = cartItem.product.price / 100;
            return cartItem;
          });
        });
      },
      me: function me(AuthService) {
        return AuthService.getLoggedInUser();
      }
    }
  });
});

app.factory('Cart', function ($http, AuthService, $rootScope, $state, $window) {
  var CartFactory = {};

  var cartUrl = '/api/me/cart';

  CartFactory.fetchCartItems = function () {
    return AuthService.getLoggedInUser().then(function (user) {
      if (user) {
        return $http.get(cartUrl).then(function (res) {
          return res.data;
        });
      } else {

        return $rootScope.cart;
      }
    });
  };

  CartFactory.removeItem = function (id) {
    return $http.delete('/api/me/cart/' + id);
  };

  CartFactory.updateQuantity = function (newNum, item) {
    return $http.put('/api/me/cart/' + item.product.id, { quantity: newNum }).then(function (res) {
      return res.data;
    });
  };

  CartFactory.clearCartUser = function (userId) {
    return $http.delete('/api/me/cart/');
  };

  CartFactory.clearCartVisitor = function () {
    return $window.sessionStorage.clear();
  };

  CartFactory.fetchNotLoggedInItems = function () {
    var toSend = [];
    for (var key in $window.sessionStorage) {
      var obj = JSON.parse($window.sessionStorage[key]);
      toSend.push({
        id: key,
        quantity: obj[1],
        product: {
          name: obj[0].name,
          price: obj[0].price,
          inventory: obj[0].inventory
        }
      });
    }
    return toSend;
  };

  return CartFactory;
});

app.config(function ($stateProvider) {
  $stateProvider.state('cart', {
    url: '/cart',
    templateUrl: 'js/cart/cart.html',
    controller: 'CartCtrl',
    resolve: {
      cartItems: function cartItems(Cart, AuthService, $rootScope) {
        return AuthService.getLoggedInUser().then(function (user) {
          if (!user) return Cart.fetchNotLoggedInItems($rootScope.cart);else return Cart.fetchCartItems();
        });
      }
    }
  });
});

app.controller('CartCtrl', function ($scope, cartItems, Cart, AuthService, $rootScope, $window) {

  $scope.cartItems = cartItems;

  function getTotal(items) {
    return _.sum(items.map(function (item) {
      return item.product.price * item.quantity;
    }));
  }

  $scope.total = getTotal($scope.cartItems);

  $scope.edit = false;

  $scope.removeItem = function (item) {
    AuthService.getLoggedInUser().then(function (user) {
      if (!user) {
        $window.sessionStorage.removeItem(item.id);
        $scope.cartItems = Cart.fetchNotLoggedInItems();
        $scope.total = getTotal($scope.cartItems);
      } else return Cart.removeItem(item.product.id);
    }).then(function () {
      if (arguments.length <= 0 ? undefined : arguments[0]) {
        var idx = $scope.cartItems.indexOf(item);
        $scope.cartItems.splice(idx, 1);
        $scope.total = getTotal($scope.cartItems);
      }
    });
  };

  $scope.editQuantity = function (newNum, item) {
    $scope.edit = false;
    if (newNum === 0) this.removeItem(item);else if (newNum <= item.product.inventory && newNum > 0) {
      AuthService.getLoggedInUser().then(function (user) {
        if (!user) {
          var userSession = $window.sessionStorage;
          var thisArr = JSON.parse(userSession.getItem(item.id)); //[product, quantity]
          thisArr[1] = newNum;
          userSession.setItem([item.id], JSON.stringify([item.product, thisArr[1]]));
          $scope.cartItems = Cart.fetchNotLoggedInItems();
          $scope.total = getTotal($scope.cartItems);
        } else {
          return Cart.updateQuantity(newNum, item);
        }
      }).then(function () {
        for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
          args[_key] = arguments[_key];
        }

        if (args[0]) {
          var idx = $scope.cartItems.indexOf(item);
          $scope.cartItems[idx].quantity = args[0].quantity;
          $scope.total = getTotal($scope.cartItems);
        }
      });
    }
  };

  $scope.editView = function () {
    $scope.edit = true;
  };
});

(function () {

  'use strict';

  // Hope you didn't forget Angular! Duh-doy.

  if (!window.angular) throw new Error('I can\'t find Angular!');

  var app = angular.module('fsaPreBuilt', []);

  app.factory('Socket', function () {
    if (!window.io) throw new Error('socket.io not found!');
    return window.io(window.location.origin);
  });

  // AUTH_EVENTS is used throughout our app to
  // broadcast and listen from and to the $rootScope
  // for important events about authentication flow.
  app.constant('AUTH_EVENTS', {
    loginSuccess: 'auth-login-success',
    loginFailed: 'auth-login-failed',
    logoutSuccess: 'auth-logout-success',
    sessionTimeout: 'auth-session-timeout',
    notAuthenticated: 'auth-not-authenticated',
    notAuthorized: 'auth-not-authorized'
  });

  app.factory('AuthInterceptor', function ($rootScope, $q, AUTH_EVENTS) {
    var statusDict = {
      401: AUTH_EVENTS.notAuthenticated,
      403: AUTH_EVENTS.notAuthorized,
      419: AUTH_EVENTS.sessionTimeout,
      440: AUTH_EVENTS.sessionTimeout
    };
    return {
      responseError: function responseError(response) {
        $rootScope.$broadcast(statusDict[response.status], response);
        return $q.reject(response);
      }
    };
  });

  app.config(function ($httpProvider) {
    $httpProvider.interceptors.push(['$injector', function ($injector) {
      return $injector.get('AuthInterceptor');
    }]);
  });

  app.service('AuthService', function ($http, Session, $rootScope, AUTH_EVENTS, $q) {

    function onSuccessfulLogin(response) {
      var data = response.data;
      Session.create(data.id, data.user);
      $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
      return data.user;
    }

    // Uses the session factory to see if an
    // authenticated user is currently registered.
    this.isAuthenticated = function () {
      return !!Session.user;
    };

    this.getLoggedInUser = function (fromServer) {

      // If an authenticated session exists, we
      // return the user attached to that session
      // with a promise. This ensures that we can
      // always interface with this method asynchronously.

      // Optionally, if true is given as the fromServer parameter,
      // then this cached value will not be used.

      if (this.isAuthenticated() && fromServer !== true) {
        return $q.when(Session.user);
      }

      // Make request GET /session.
      // If it returns a user, call onSuccessfulLogin with the response.
      // If it returns a 401 response, we catch it and instead resolve to null.
      return $http.get('/session').then(onSuccessfulLogin).catch(function () {
        return null;
      });
    };

    this.login = function (credentials) {
      return $http.post('/login', credentials).then(onSuccessfulLogin).catch(function () {
        return $q.reject({ message: 'Invalid login credentials.' });
      });
    };

    this.logout = function () {
      return $http.get('/logout').then(function () {
        Session.destroy();
        $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
      });
    };
  });

  app.service('Session', function ($rootScope, AUTH_EVENTS) {

    var self = this;

    $rootScope.$on(AUTH_EVENTS.notAuthenticated, function () {
      self.destroy();
    });

    $rootScope.$on(AUTH_EVENTS.sessionTimeout, function () {
      self.destroy();
    });

    this.id = null;
    this.user = null;

    this.create = function (sessionId, user) {
      this.id = sessionId;
      this.user = user;
    };

    this.destroy = function () {
      this.id = null;
      this.user = null;
    };
  });
})();

app.config(function ($stateProvider) {
  $stateProvider.state('home', {
    url: '/',
    templateUrl: 'js/home/home.html'
  });
});

app.factory('Login', function ($http, $rootScope, $q) {
  var loginFactory = {};

  loginFactory.persistPseudoCart = function (cartObj) {
    var promiseArr = [];
    for (var productId in cartObj) {
      promiseArr.push($http.post('/api/me/cart/' + productId, { quantity: cartObj[productId][1] }));
    }
    delete $rootScope.cart;
    return $q.all(promiseArr);
  };

  return loginFactory;
});

app.config(function ($stateProvider) {

  $stateProvider.state('login', {
    url: '/login',
    templateUrl: 'js/login/login.html',
    controller: 'LoginCtrl'
  });
});

app.controller('LoginCtrl', function ($scope, AuthService, $state, $rootScope, Login, ResetPassword) {

  $scope.login = {};
  $scope.error = null;

  $scope.sendLogin = function (loginInfo) {

    $scope.error = null;

    AuthService.login(loginInfo).then(function () {
      if ($rootScope.cart) {
        return Login.persistPseudoCart($rootScope.cart);
      }
    }).then(function () {
      $state.go('home');
    }).catch(function () {
      $scope.error = 'Invalid login credentials.';
    });
  };
});

app.config(function ($stateProvider) {

  $stateProvider.state('passwordreset', {
    url: '/reset/:hashId',
    templateUrl: 'js/passwordReset/reset.html',
    controller: 'resetCtrl'
  });

  $stateProvider.state('forgotPassword', {
    url: '/forgotpassword',
    templateUrl: 'js/passwordReset/forgotPassword.html',
    controller: 'forgotPasswordCtrl'
  });
});

app.factory('ResetPassword', function ($http) {
  return {
    checkHashRoute: function checkHashRoute(hash) {
      return $http.get('/api/password/resetPassword/?uw=' + hash).then(function (res) {
        return res.data;
      });
    },
    resetUserPassword: function resetUserPassword(data) {
      return $http.put('/api/password/resetPassword', data).then(function (res) {
        return res.data;
      });
    },
    sendForgotEmail: function sendForgotEmail(email) {
      return $http.post('/api/mailer/resetPassword', { email: email }).then(function (res) {
        return res.data;
      });
    }
  };
});

app.controller('resetCtrl', function ($scope, $stateParams, ResetPassword, User) {
  var hashId = $stateParams.hashId;
  var password = $scope.password;
  $scope.passwordResetComplete = false;
  $scope.error = null;

  $scope.resetPassword = function (password) {
    ResetPassword.checkHashRoute(hashId).then(function (email) {
      if (email) {
        var reqBody = { email: email, password: password };
        return ResetPassword.resetUserPassword(reqBody);
      } else {
        console.error('no email found');
      }
    }).then(function (updatedUser) {
      $scope.passwordResetComplete = true;
    }).catch(function (error) {
      $scope.error = 'For your security, we\'ve timed out the password reset request.  Please click Forgot Password again and come back :)';
    });
  };
});

app.controller('forgotPasswordCtrl', function ($scope, ResetPassword) {
  var emailAddress = $scope.email;
  $scope.emailSent = false;
  $scope.sendForgotEmail = function (emailAddress) {
    ResetPassword.sendForgotEmail(emailAddress).then(function (data) {
      $scope.emailSent = true;
    });
  };
});

app.controller('ProfileCtrl', function ($scope, me) {
  $scope.me = me;
});

app.config(function ($stateProvider) {
  $stateProvider.state('profile', {
    url: '/profile',
    templateUrl: 'js/profile/profile.html',
    controller: 'ProfileCtrl',
    resolve: {
      me: function me(User, AuthService) {
        return AuthService.getLoggedInUser();
      }
    }
  });
});

app.config(function ($stateProvider) {
  $stateProvider.state('signup', {
    url: '/signup',
    templateUrl: 'js/signup/signup.html',
    controller: 'signUpCtrl'
  });
});

app.controller('signUpCtrl', function ($scope, User, AuthService, $state, $rootScope, Login, $window, Mailer) {
  $scope.error = null;

  $scope.sendSignup = function (signupInfo) {
    //Error handling in controller to keep HTML
    //easy to deal with instead of having a bunch
    //of hidden divs and spans
    if ($scope.signupForm.$error.email) $scope.error = 'Please enter a valid email';else if ($scope.signupForm.$error.minlength) $scope.error = 'Password must be at least 8 characters';else if ($scope.signupForm.$error.maxlength) $scope.error = 'Password must be less than 32 characters';else if ($scope.signupForm.$error.required) $scope.error = 'All fields are required';else {
      User.signup(signupInfo).then(function () {
        //log user in if the signup was successful
        return AuthService.login({ email: signupInfo.email, password: signupInfo.password });
      }).then(function () {
        var cart = {};
        for (var key in $window.sessionStorage) {
          var obj = JSON.parse($window.sessionStorage[key]);
          cart[key] = obj;
        }
        if (cart) {
          return Login.persistPseudoCart(cart);
        }
      }).then(function () {
        return Mailer.sendWelcomeMessage(signupInfo);
      }).then(function () {
        return $state.go('home');
      }).catch(function (err) {
        $scope.error = 'There was an error. Error 432052. Please contact Payton';
      });
    };
  };
});

app.controller('adminOrdersCtrl', function ($scope, orders) {
  $scope.orders = orders;
});

app.controller('adminOrderDetailCtrl', function ($scope, Order, $stateParams, Address, $state, $q) {
  var orderId = $stateParams.orderId;
  $scope.order = {};
  Order.getOneOrderSummary(orderId).then(function (orderSummary) {
    $scope.order.orderSummary = orderSummary;
    return Address.getOneAddress(orderSummary.shippingId);
  }).then(function (address) {
    $scope.order.orderAddress = address;
    return Order.getAllOrderDetails(orderId);
  }).then(function (orderDetails) {
    return $scope.order.orderDetails = orderDetails;
  }).catch(function (error) {
    return console.error(error);
  });

  $scope.saveChanges = function (order) {
    var orderSummary = order.orderSummary; //THIS AN OBJ
    var orderDetails = order.orderDetails; //THIS IS AN ARRAY

    Order.updateOneOrderSummary(orderSummary.id, orderSummary).then(function () {
      return Promise.all(orderDetails.map(function (orderDetail) {
        return Order.updateOrderDetails(orderDetail.id, orderDetail);
      }));
    }).then(function (details) {
      //Now we check if all details are processed to change the master summary 'processed'
      var processed = void 0;
      details.filter(function (detail) {
        return !detail.processed;
      }).length > 0 ? processed = false : processed = true;
      return Order.updateOneOrderSummary(orderSummary.id, { processed: processed });
    }).then(function () {
      return $state.go('admin.orders');
    }).catch(function (error) {
      return console.error(error);
    });
  };
});

app.controller('adminCtrl', function () {
  //EMPTY FOR NOW
});

app.config(function ($stateProvider) {
  $stateProvider.state('admin', {
    url: '/admin',
    templateUrl: 'js/admin/home/admin.html',
    resolve: {
      authAdmin: function authAdmin(AuthService, $rootScope, $state) {
        return AuthService.getLoggedInUser().then(function (user) {
          if (!user.isAdmin) $state.go('home');else $rootScope.isAdmin = true;
        });
      }
    },
    controller: 'adminCtrl'
  }).state('admin.users', {
    url: '/users',
    templateUrl: 'js/admin/users/users.admin.html',
    controller: 'usersAdminCtrl'
  }).state('admin.userDetail', {
    url: '/users/:userId',
    templateUrl: 'js/admin/users/user.detail.admin.html',
    controller: 'usersDetailAdminCtrl'
  }).state('admin.products', {
    url: '/products',
    templateUrl: 'js/admin/products/products.admin.html',
    controller: 'adminProductsCtrl'
  }).state('admin.productDetail', {
    url: '/products/:productId',
    templateUrl: 'js/admin/products/product.detail.admin.html',
    controller: 'adminProductDetailCtrl'
  }).state('admin.orders', {
    url: '/orders',
    templateUrl: 'js/admin/orders/orders.admin.html',
    controller: 'adminOrdersCtrl',
    resolve: {
      orders: function orders(Order) {
        return Order.getAllOrderSummaries().then(function (orders) {
          return orders;
        }).catch(function (error) {
          return console.error(error);
        });
      }
    }
  }).state('admin.orderDetail', {
    url: '/orders/:orderId',
    templateUrl: 'js/admin/orders/order.detail.admin.html',
    controller: 'adminOrderDetailCtrl'
  });
});

'use strict';

app.controller('adminProductsCtrl', function ($scope, Product, $rootScope) {

  $rootScope.$on('searching', function (e, data) {
    $scope.search = data;
  });

  Product.getAll().then(function (products) {
    $scope.products = products;
  }).catch(function (error) {
    console.log(error);
  });
});

app.controller('adminProductDetailCtrl', function ($scope, $state, Product, $stateParams) {
  var productId = $stateParams.productId;

  Product.getOne(productId).then(function (product) {
    return $scope.product = product;
  }).catch(function (error) {
    return console.error(error);
  });

  $scope.saveChanges = function (formData) {
    Product.editOne(productId, formData).then(function (updatedProduct) {
      return $state.go('admin.products');
    });
  };
});

app.controller('usersAdminCtrl', function ($scope, User, $rootScope) {

  $rootScope.$on('searching', function (e, data) {
    $scope.search = data;
  });
  //Get all and add to scope
  User.getAll().then(function (users) {
    return $scope.users = users;
  }).catch(function (error) {
    return console.error(error);
  });
});

app.controller('usersDetailAdminCtrl', function ($scope, User, $stateParams, $state) {
  var userId = parseInt($stateParams.userId);

  //Get all and add to scope
  User.getOne(userId).then(function (user) {
    $scope.user = user;
  }).catch(function (error) {
    return console.error(error);
  });

  $scope.saveChanges = function (formData) {
    User.editOne(userId, formData).then(function () {
      return $state.go('admin.users');
    }).catch(function (error) {
      return console.error(error);
    });
  };
});

'use strict';

app.factory('Address', function ($http) {
  return {
    getMyAddresses: function getMyAddresses() {
      return $http.get('/api/me/addresses').then(function (res) {
        return res.data;
      });
    },
    createNewAddress: function createNewAddress(information, user) {
      if (user) {
        return $http.post('/api/me/addresses', information).then(function (res) {
          return res.data;
        });
      } else {
        return $http.post('/api/address', information).then(function (res) {
          return res.data;
        });
      }
    },
    getOneAddress: function getOneAddress(id) {
      return $http.get('/api/address/' + id).then(function (res) {
        return res.data;
      });
    },
    removeAddressFromUser: function removeAddressFromUser(addressId, userId) {
      return $http.delete('/api/address/' + addressId + '/' + userId).then(function (res) {
        return res.data;
      });
    }
  };
});

'use strict';

app.factory('Card', function ($http) {
  return {
    getMyCards: function getMyCards() {
      return $http.get('/api/me/cards').then(function (res) {
        return res.data;
      });
    },
    createNewCardForUser: function createNewCardForUser(card) {
      return $http.post('/api/me/cards', card).then(function (res) {
        return res.data;
      });
    },
    createNewCardNoUser: function createNewCardNoUser(card) {
      return $http.post('/api/card', card).then(function (res) {
        return res.data;
      });
    },
    removeCardFromUser: function removeCardFromUser(cardId, userId) {
      return $http.delete('/api/card/' + cardId + '/' + userId).then(function (res) {
        return res.data;
      });
    }
  };
});

app.factory('FullstackPics', function () {
  return ['https://pbs.twimg.com/media/B7gBXulCAAAXQcE.jpg:large', 'https://fbcdn-sphotos-c-a.akamaihd.net/hphotos-ak-xap1/t31.0-8/10862451_10205622990359241_8027168843312841137_o.jpg', 'https://pbs.twimg.com/media/B-LKUshIgAEy9SK.jpg', 'https://pbs.twimg.com/media/B79-X7oCMAAkw7y.jpg', 'https://pbs.twimg.com/media/B-Uj9COIIAIFAh0.jpg:large', 'https://pbs.twimg.com/media/B6yIyFiCEAAql12.jpg:large', 'https://pbs.twimg.com/media/CE-T75lWAAAmqqJ.jpg:large', 'https://pbs.twimg.com/media/CEvZAg-VAAAk932.jpg:large', 'https://pbs.twimg.com/media/CEgNMeOXIAIfDhK.jpg:large', 'https://pbs.twimg.com/media/CEQyIDNWgAAu60B.jpg:large', 'https://pbs.twimg.com/media/CCF3T5QW8AE2lGJ.jpg:large', 'https://pbs.twimg.com/media/CAeVw5SWoAAALsj.jpg:large', 'https://pbs.twimg.com/media/CAaJIP7UkAAlIGs.jpg:large', 'https://pbs.twimg.com/media/CAQOw9lWEAAY9Fl.jpg:large', 'https://pbs.twimg.com/media/B-OQbVrCMAANwIM.jpg:large', 'https://pbs.twimg.com/media/B9b_erwCYAAwRcJ.png:large', 'https://pbs.twimg.com/media/B5PTdvnCcAEAl4x.jpg:large', 'https://pbs.twimg.com/media/B4qwC0iCYAAlPGh.jpg:large', 'https://pbs.twimg.com/media/B2b33vRIUAA9o1D.jpg:large', 'https://pbs.twimg.com/media/BwpIwr1IUAAvO2_.jpg:large', 'https://pbs.twimg.com/media/BsSseANCYAEOhLw.jpg:large', 'https://pbs.twimg.com/media/CJ4vLfuUwAAda4L.jpg:large', 'https://pbs.twimg.com/media/CI7wzjEVEAAOPpS.jpg:large', 'https://pbs.twimg.com/media/CIdHvT2UsAAnnHV.jpg:large', 'https://pbs.twimg.com/media/CGCiP_YWYAAo75V.jpg:large', 'https://pbs.twimg.com/media/CIS4JPIWIAI37qu.jpg:large'];
});

app.factory('Mailer', function ($http) {
  return {
    sendWelcomeMessage: function sendWelcomeMessage(data) {
      return $http.post('/api/mailer/welcomeMessage', data).then(function (res) {
        return res.data;
      });
    }
  };
});

'use strict';

app.factory('Order', function ($http) {
  return {
    getAllOrderSummaries: function getAllOrderSummaries() {
      return $http.get('/api/orders').then(function (res) {
        return res.data;
      });
    },
    getMyOrderSummaries: function getMyOrderSummaries() {
      return $http.get('/api/me/orders').then(function (res) {
        return res.data;
      });
    },
    getMyOrderDetails: function getMyOrderDetails(orderSummaryId) {
      return $http.get('/api/me/orders/' + orderSummaryId).then(function (res) {
        return res.data;
      });
    },
    getOneOrderSummary: function getOneOrderSummary(orderSummaryId) {
      return $http.get('/api/orders/' + orderSummaryId).then(function (res) {
        return res.data;
      });
    },
    updateOneOrderSummary: function updateOneOrderSummary(orderSummaryId, data) {
      return $http.put('/api/orders/' + orderSummaryId, data).then(function (res) {
        return res.data;
      });
    },
    updateOrderDetails: function updateOrderDetails(orderDetailsId, data) {
      return $http.put('/api/orders/details/' + orderDetailsId, data).then(function (res) {
        return res.data;
      });
    },
    getAllOrderDetails: function getAllOrderDetails(orderSummaryId) {
      return $http.get('/api/orders/' + orderSummaryId + '/details').then(function (res) {
        return res.data;
      });
    },

    sendToStripe: function sendToStripe(chargeDetails) {
      return $http.post('/api/card/stripe', chargeDetails).then(function (res) {
        return res.data;
      });
    },

    createOrderSummary: function createOrderSummary(orderData) {
      orderData.priceTotal *= 100;
      return $http.post('/api/orders', orderData).then(function (res) {
        return res.data;
      });
    },

    createOrderDetails: function createOrderDetails(orderDetails) {
      return $http.post('/api/orders/details', orderDetails).then(function (res) {
        return res.data;
      });
    }
  };
});

'use strict';

app.factory('Product', function ($http) {

  var ProductFactory = {};

  ProductFactory.url = '/api/products';

  ProductFactory.getAll = function (query) {
    if (!query) query = '';
    return $http.get(ProductFactory.url + query).then(function (res) {
      return res.data;
    });
  };

  ProductFactory.getOne = function (id) {
    return $http.get(ProductFactory.url + '/' + id).then(function (res) {
      return res.data;
    });
  };

  ProductFactory.editOne = function (id, data) {
    return $http.put(ProductFactory.url + '/' + id, data).then(function (res) {
      return res.data;
    });
  };

  return ProductFactory;
});

app.factory('ReviewFactory', function ($http) {
  return {
    addReview: function addReview(review, productId) {
      return $http.post('/api/reviews/' + productId, { stars: review.stars, description: review.description });
    },
    getReviews: function getReviews(productId) {
      return $http.get('/api/reviews/' + productId).then(function (res) {
        return res.data;
      });
    }
  };
});

'use strict';

app.factory('User', function ($http) {
  return {
    signup: function signup(signupData) {
      return $http.post('/api/users', signupData).then(function (res) {
        return res.data;
      });
    },

    getAll: function getAll() {
      return $http.get('/api/users').then(function (res) {
        return res.data;
      });
    },

    getOne: function getOne(id) {
      return $http.get('/api/users/' + id).then(function (res) {
        return res.data;
      });
    },

    editOne: function editOne(id, data) {
      return $http.put('/api/users/' + id, data).then(function (res) {
        return res.data;
      });
    }
  };
});

'use strict';

app.factory('Utility', function ($http) {
  return {
    convertCentsToDollars: function convertCentsToDollars(cents) {
      return cents / 100;
    },

    convertDollarsToCents: function convertDollarsToCents(dollars) {
      return dollars * 100;
    },

    convertToQuery: function convertToQuery(json) {
      var superQuery = [];
      for (var key in json) {
        if (json.hasOwnProperty(key)) {
          superQuery.push(json[key]);
        }
      }
      superQuery = '?' + superQuery.join('&');

      return superQuery;
    }
  };
});

app.controller('ProductDetailCtrl', function ($scope, product, productReviews, ReviewFactory) {
  $scope.viewReviews = false;
  $scope.addReview = false;
  $scope.product = product;
  $scope.productReviews = productReviews;
});

app.directive('addReview', function ($state, ReviewFactory) {
  return {
    restrict: 'E',
    templateUrl: 'js/product/detail/addReview.html',
    link: function link(scope, elem, attrs) {
      scope.stars = [1, 2, 3, 4, 5];
      scope.submitReview = function (review, productId) {
        ReviewFactory.addReview(review, productId);
        $state.go('cart');
      };
    }
  };
});

app.directive('viewReviews', function ($state, ReviewFactory) {
  return {
    restrict: 'E',
    templateUrl: 'js/product/detail/viewReviews.html'
  };
});

app.config(function ($stateProvider) {
  $stateProvider.state('product', {
    url: '/products/:id',
    templateUrl: 'js/product/detail/product.detail.html',
    controller: 'ProductDetailCtrl',
    resolve: {
      product: function product(Product, $stateParams) {
        return Product.getOne($stateParams.id);
      },
      productReviews: function productReviews(ReviewFactory, $stateParams) {
        return ReviewFactory.getReviews($stateParams.id);
      }
    }
  });
});

app.factory('ProductListFactory', function ($window, $http, AuthService, $rootScope, $q) {

  var ProductListFactory = {};

  ProductListFactory.addProduct = function (product, quantity) {
    console.log('----------Here--------', product);
    $rootScope.cart = $rootScope.cart || {};
    return AuthService.getLoggedInUser().then(function (user) {
      if (!user) {
        var userSession = $window.sessionStorage;
        if (userSession.getItem(product.id)) {
          var thisArr = JSON.parse(userSession.getItem(product.id)); //[product, quantity]
          thisArr[1] += quantity;
          userSession.setItem([product.id], JSON.stringify([product, thisArr[1]]));
        } else {
          userSession.setItem([product.id], JSON.stringify([product, quantity]));
        }
      } else {
        return $http.post('/api/me/cart/' + product.id, { quantity: quantity });
      }
    }).then(function () {
      for (var _len2 = arguments.length, args = Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
        args[_key2] = arguments[_key2];
      }

      if (args[0]) return args[0].data;
    });
  };

  return ProductListFactory;
});

app.controller('ProductListCtrl', function ($scope, products, Product, Utility) {
  $scope.products = products;
  $scope.filterObj = {};

  $scope.addToFilter = function (property, query) {
    $scope.filterObj[property] = query;
    var superQuery = Utility.convertToQuery($scope.filterObj);
    Product.getAll(superQuery).then(function (products) {
      $scope.products = products;
    });
  };

  $scope.removeFromFilter = function (property) {
    delete $scope.filterObj[property];
    var superQuery = Utility.convertToQuery($scope.filterObj);
    Product.getAll(superQuery).then(function (products) {
      $scope.products = products;
    });
  };

  $scope.changeFilter = function (property, query, theCheck) {
    if ($scope[theCheck]) {
      $scope.addToFilter(property, query);
    } else {
      $scope.removeFromFilter(property);
    }
  };
});

app.config(function ($stateProvider) {
  $stateProvider.state('products', {
    url: '/products',
    templateUrl: 'js/product/list/product.list.html',
    controller: 'ProductListCtrl',
    resolve: {
      products: function products(Product) {
        return Product.getAll();
      }
    }
  });
});

app.controller('ProfileAddressCtrl', function ($scope, addresses, Address, $rootScope) {
  $rootScope.addresses = addresses;
});

app.config(function ($stateProvider) {
  $stateProvider.state('profile.addresses', {
    url: '/addresses',
    templateUrl: 'js/profile/addresses/myaddresses.html',
    controller: 'ProfileAddressCtrl',
    resolve: {
      addresses: function addresses(Address) {
        return Address.getMyAddresses();
      }
    }
  });
});

app.controller('ProfileOrdersCtrl', function ($scope, orderSummaries, Order) {
  $scope.orderSummaries = orderSummaries;
});

app.config(function ($stateProvider) {
  $stateProvider.state('profile.orders', {
    url: '/orders',
    templateUrl: 'js/profile/orders/myorders.html',
    controller: 'ProfileOrdersCtrl',
    resolve: {
      orderSummaries: function orderSummaries(Order) {
        return Order.getMyOrderSummaries();
      }
    }
  });
});

app.controller('ProfileCardsCtrl', function ($scope, cards, $rootScope) {
  $rootScope.cards = cards;
});

app.config(function ($stateProvider) {
  $stateProvider.state('profile.cards', {
    url: '/cards',
    templateUrl: 'js/profile/cards/cards.html',
    controller: 'ProfileCardsCtrl',
    resolve: {
      cards: function cards(Card) {
        return Card.getMyCards();
      }
    }
  });
});

app.directive('adminNav', function (AuthService, $rootScope) {
  return {
    restrict: 'E',
    scope: {},
    templateUrl: 'js/admin/directives/html/nav.admin.html',
    link: function link(scope) {
      var setUser = function setUser() {
        AuthService.getLoggedInUser().then(function (user) {
          scope.user = user;
        });
      };
      scope.search = {
        adminSearch: ''
      };

      scope.searching = function () {
        $rootScope.$broadcast('searching', scope.search);
      };
      setUser();
    }
  };
});

app.directive('productListAdmin', function () {
  return {
    restrict: 'E',
    templateUrl: 'js/admin/directives/html/product.list.admin.html'
  };
});

app.directive('userListAdmin', function () {
  return {
    restrict: 'E',
    templateUrl: 'js/admin/directives/html/users.list.admin.html'
  };
});

'use strict';

app.directive('addressForm', function ($rootScope, Address) {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/address/address-form.html',
    link: function link(scope, elem, attrs) {
      scope.createAddress = function (information, user) {
        Address.createNewAddress(information, user).then(function (address) {
          $rootScope.addresses.push(address);
          scope.information = {};
          scope.addAddress.$setPristine();
        });
      };
    }
  };
});

'use strict';

app.directive('address', function ($rootScope, Address) {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/address/address.html',
    scope: {
      address: '=model'
    },
    link: function link(scope, elem, attrs) {
      scope.deleteAddress = function (addressId, userId) {
        Address.removeAddressFromUser(addressId, userId).then(function () {
          $rootScope.addresses.forEach(function (address, i) {
            if (address.id === addressId) {
              $rootScope.addresses.splice(i, 1);
            }
          });
        }).catch(function (error) {
          return console.error(error);
        });
      };
    }
  };
});

app.directive('fullstackLogo', function () {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/fullstack-logo/fullstack-logo.html'
  };
});
app.directive('payment', function ($rootScope, AuthService, AUTH_EVENTS, $state) {

  return {
    restrict: 'E',
    scope: {},
    templateUrl: 'js/common/directives/checkout/payment.html',
    link: function link(scope) {
      scope.submitPayment = function (checkout) {
        //we must add createPayment to the order factory
        order.createPayment($scope.newOrder).then(function () {
          // show confirmation modal
          $uibModal.open({
            templateUrl: '/js/checkout/confirmation.html',
            controller: ['$scope', '$uibModalInstance', '$state', function ($scope, $uibModalInstance, $state) {
              $scope.ok = function () {
                $uibModalInstance.close();
              };
            }]
          });
          $state.go('products');
        }).catch(function (error) {
          return console.error(error);
        });
      };
    }
  };
});

app.directive('navbar', function ($rootScope, AuthService, AUTH_EVENTS, $state) {

  return {
    restrict: 'E',
    scope: {},
    templateUrl: 'js/common/directives/navbar/navbar.html',
    link: function link(scope) {

      scope.items = [{ label: 'Home', state: 'home' }, { label: 'Products', state: 'products' }];
      scope.isAdmin = false;
      scope.user = null;

      scope.isLoggedIn = function () {
        return AuthService.isAuthenticated();
      };

      scope.logout = function () {
        AuthService.logout().then(function () {
          $state.go('home');
        });
      };

      var setUser = function setUser() {
        AuthService.getLoggedInUser().then(function (user) {
          scope.user = user;
          if (scope.user.isAdmin) scope.isAdmin = true;
        });
      };

      var removeUser = function removeUser() {
        scope.user = null;
        scope.isAdmin = false;
      };

      setUser();

      $rootScope.$on(AUTH_EVENTS.loginSuccess, setUser);
      $rootScope.$on(AUTH_EVENTS.logoutSuccess, removeUser);
      $rootScope.$on(AUTH_EVENTS.sessionTimeout, removeUser);
    }

  };
});

'use strict';

app.directive('orderDetail', function (Order) {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/orders/order.detail.html',
    scope: {
      orderDetail: '=model'
    }
  };
});

'use strict';

app.directive('orderSummary', function (Order, AuthService, $rootScope) {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/orders/order.summary.html',
    scope: {
      orderSummary: '=model'
    },
    link: function link(scope, elem, attrs) {
      scope.details = {};
      scope.show = {};
      scope.orderSummary.priceTotal = scope.orderSummary.priceTotal / 100;

      function getOrderDetails(id) {
        if (scope.details[id]) scope.show[id] = true;else {
          if ($rootScope.isAdmin) {
            Order.getAllOrderDetails(id).then(function (details) {
              scope.show[id] = true;
              scope.details[id] = details;
            });
          } else {
            Order.getMyOrderDetails(id).then(function (details) {
              scope.show[id] = true;
              scope.details[id] = details;
            });
          }
        }
      }

      scope.toggle = function (id) {
        if (scope.show[id]) scope.show[id] = false;else getOrderDetails(id);
      };
    }
  };
});

'use strict';

app.directive('cardForm', function (Card, $rootScope) {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/payment-cards/card-form.html',
    scope: {
      userId: '='
    },
    link: function link(scope, elem, attrs) {
      scope.submitCard = function (card) {
        if (scope.userId) {
          Card.createNewCardForUser(card).then(function (card) {
            return $rootScope.cards.push(card);
          });
        } else Card.createNewCardNoUser(card).then(function (card) {
          return $rootScope.cards.push(card);
        });
      };
    }
  };
});

'use strict';

app.directive('paymentCard', function () {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/payment-cards/payment-card.html',
    scope: {
      card: '=model'
    }
  };
});

'use strict';

app.directive('addToCart', function (ProductListFactory, $state) {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/products/product.add-to-cart.html',
    scope: {
      product: '=model'
    },
    link: function link(scope, elem, attrs) {
      scope.added = false;
      scope.quantities = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      scope.quantity = scope.quantities[0];
      scope.addToCart = function (product) {
        scope.added = true;
        ProductListFactory.addProduct(product, scope.quantity).then(function () {
          $state.go('cart');
        });
      };
    }
  };
});

'use strict';

app.directive('productList', function () {
  return {
    restrict: 'E',
    templateUrl: 'js/common/directives/products/product.list.html',
    scope: {
      product: '=model'
    },
    link: function link(scope, elem, attrs) {
      scope.product.description = scope.product.description.substring(0, 100);
    }
  };
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImNoZWNrb3V0L2NoZWNrb3V0LmpzIiwiY2hlY2tvdXQvY2hlY2tvdXQuc3RhdGUuanMiLCJjYXJ0L2NhcnQuanMiLCJmc2EvZnNhLXByZS1idWlsdC5qcyIsImhvbWUvaG9tZS5qcyIsImxvZ2luL2xvZ2luLmpzIiwicGFzc3dvcmRSZXNldC9yZXNldC5qcyIsInByb2ZpbGUvcHJvZmlsZS5jb250cm9sbGVyLmpzIiwicHJvZmlsZS9wcm9maWxlLnN0YXRlLmpzIiwic2lnbnVwL3NpZ251cC5qcyIsImFkbWluL29yZGVycy9vcmRlcnMuYWRtaW4uanMiLCJhZG1pbi9ob21lL2FkbWluLmpzIiwiYWRtaW4vaG9tZS9hZG1pbi5zdGF0ZS5qcyIsImFkbWluL3Byb2R1Y3RzL3Byb2R1Y3RzLmFkbWluLmpzIiwiYWRtaW4vdXNlcnMvdXNlcnMuYWRtaW4uanMiLCJjb21tb24vZmFjdG9yaWVzL0FkZHJlc3MuanMiLCJjb21tb24vZmFjdG9yaWVzL0NhcmQuanMiLCJjb21tb24vZmFjdG9yaWVzL0Z1bGxzdGFja1BpY3MuanMiLCJjb21tb24vZmFjdG9yaWVzL01haWxlci5qcyIsImNvbW1vbi9mYWN0b3JpZXMvT3JkZXIuanMiLCJjb21tb24vZmFjdG9yaWVzL1Byb2R1Y3QuanMiLCJjb21tb24vZmFjdG9yaWVzL1Jldmlldy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvVXNlci5qcyIsImNvbW1vbi9mYWN0b3JpZXMvVXRpbGl0eS5qcyIsInByb2R1Y3QvZGV0YWlsL3Byb2R1Y3QuZGV0YWlsLmpzIiwicHJvZHVjdC9kZXRhaWwvcHJvZHVjdC5kZXRhaWwuc3RhdGUuanMiLCJwcm9kdWN0L2xpc3QvcHJvZHVjdC5saXN0LmZhY3RvcnkuanMiLCJwcm9kdWN0L2xpc3QvcHJvZHVjdC5saXN0LmpzIiwicHJvZHVjdC9saXN0L3Byb2R1Y3QubGlzdC5zdGF0ZS5qcyIsInByb2ZpbGUvYWRkcmVzc2VzL215YWRkcmVzc2VzLmNvbnRyb2xsZXIuanMiLCJwcm9maWxlL2FkZHJlc3Nlcy9teWFkZHJlc3Nlcy5zdGF0ZS5qcyIsInByb2ZpbGUvb3JkZXJzL215b3JkZXJzLmNvbnRyb2xsZXIuanMiLCJwcm9maWxlL29yZGVycy9teW9yZGVycy5zdGF0ZS5qcyIsInByb2ZpbGUvY2FyZHMvY2FyZHMuY29udHJvbGxlci5qcyIsInByb2ZpbGUvY2FyZHMvY2FyZHMuc3RhdGUuanMiLCJhZG1pbi9kaXJlY3RpdmVzL2pzL25hdi5hZG1pbi5qcyIsImFkbWluL2RpcmVjdGl2ZXMvanMvcHJvZHVjdC5saXN0LmFkbWluLmpzIiwiYWRtaW4vZGlyZWN0aXZlcy9qcy91c2VyLmxpc3QuYWRtaW4uanMiLCJjb21tb24vZGlyZWN0aXZlcy9hZGRyZXNzL2FkZHJlc3MtZm9ybS5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2FkZHJlc3MvYWRkcmVzcy5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2Z1bGxzdGFjay1sb2dvL2Z1bGxzdGFjay1sb2dvLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvY2hlY2tvdXQvcGF5bWVudC5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy9vcmRlcnMvb3JkZXIuZGV0YWlsLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvb3JkZXJzL29yZGVyLnN1bW1hcnkuanMiLCJjb21tb24vZGlyZWN0aXZlcy9wYXltZW50LWNhcmRzL2NhcmQtZm9ybS5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL3BheW1lbnQtY2FyZHMvcGF5bWVudC1jYXJkLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvcHJvZHVjdHMvcHJvZHVjdC5hZGRUb0NhcnQuanMiLCJjb21tb24vZGlyZWN0aXZlcy9wcm9kdWN0cy9wcm9kdWN0Lmxpc3QuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7O0FBQ0EsT0FBQSxHQUFBLEdBQUEsUUFBQSxNQUFBLENBQUEsdUJBQUEsRUFBQSxDQUFBLGFBQUEsRUFBQSxXQUFBLEVBQUEsY0FBQSxF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QSxDQUFBO0FBQ0EsR0FGQTs7QUFJQSxjQUFBLGNBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxXQUFBLE1BQUEsR0FBQSxDQUFBLGtCQUFBLEtBQUEsT0FBQSxDQUFBLEVBQUEsRUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLEVBQ0EsSUFEQSxDQUNBO0FBQUEsYUFBQSxJQUFBLElBQUE7QUFBQSxLQURBLENBQUE7QUFFQSxHQUhBOztBQUtBLGNBQUEsYUFBQSxHQUFBLFVBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxNQUFBLE1BQUEsQ0FBQSxlQUFBLENBQUE7QUFDQSxHQUZBOztBQUlBLGNBQUEsZ0JBQUEsR0FBQSxZQUFBO0FBQ0EsV0FBQSxRQUFBLGNBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxHQUZBOztBQUlBLGNBQUEscUJBQUEsR0FBQSxZQUFBO0FBQ0EsUUFBQSxTQUFBLEVBQUE7QUFDQSxTQUFBLElBQUEsR0FBQSxJQUFBLFFBQUEsY0FBQSxFQUFBO0FBQ0EsVUFBQSxNQUFBLEtBQUEsS0FBQSxDQUFBLFFBQUEsY0FBQSxDQUFBLEdBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxJQUFBLENBQUE7QUFDQSxZQUFBLEdBREE7QUFFQSxrQkFBQSxJQUFBLENBQUEsQ0FGQTtBQUdBLGlCQUFBO0FBQ0EsZ0JBQUEsSUFBQSxDQUFBLEVBQUEsSUFEQTtBQUVBLGlCQUFBLElBQUEsQ0FBQSxFQUFBLEtBRkE7QUFHQSxxQkFBQSxJQUFBLENBQUEsRUFBQTtBQUhBO0FBSEEsT0FBQTtBQVNBO0FBQ0EsV0FBQSxNQUFBO0FBQ0EsR0FmQTs7QUFpQkEsU0FBQSxXQUFBO0FBQ0EsQ0F0REE7O0FBd0RBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsaUJBQUEsS0FBQSxDQUFBLE1BQUEsRUFBQTtBQUNBLFNBQUEsT0FEQTtBQUVBLGlCQUFBLG1CQUZBO0FBR0EsZ0JBQUEsVUFIQTtBQUlBLGFBQUE7QUFDQSxpQkFBQSxtQkFBQSxJQUFBLEVBQUEsV0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLGVBQUEsWUFBQSxlQUFBLEdBQ0EsSUFEQSxDQUNBLGdCQUFBO0FBQ0EsY0FBQSxDQUFBLElBQUEsRUFBQSxPQUFBLEtBQUEscUJBQUEsQ0FBQSxXQUFBLElBQUEsQ0FBQSxDQUFBLEtBQ0EsT0FBQSxLQUFBLGNBQUEsRUFBQTtBQUNBLFNBSkEsQ0FBQTtBQUtBO0FBUEE7QUFKQSxHQUFBO0FBY0EsQ0FmQTs7QUFpQkEsSUFBQSxVQUFBLENBQUEsVUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUEsV0FBQSxFQUFBLFVBQUEsRUFBQSxPQUFBLEVBQUE7O0FBRUEsU0FBQSxTQUFBLEdBQUEsU0FBQTs7QUFFQSxXQUFBLFFBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsR0FBQSxDQUFBLE1BQUEsR0FBQSxDQUFBO0FBQUEsYUFBQSxLQUFBLE9BQUEsQ0FBQSxLQUFBLEdBQUEsS0FBQSxRQUFBO0FBQUEsS0FBQSxDQUFBLENBQUE7QUFDQTs7QUFFQSxTQUFBLEtBQUEsR0FBQSxTQUFBLE9BQUEsU0FBQSxDQUFBOztBQUVBLFNBQUEsSUFBQSxHQUFBLEtBQUE7O0FBRUEsU0FBQSxVQUFBLEdBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSxnQkFBQSxlQUFBLEdBQ0EsSUFEQSxDQUNBLGdCQUFBO0FBQ0EsVUFBQSxDQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLGNBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZUFBQSxTQUFBLEdBQUEsS0FBQSxxQkFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLEdBQUEsU0FBQSxPQUFBLFNBQUEsQ0FBQTtBQUNBLE9BSkEsTUFLQSxPQUFBLEtBQUEsVUFBQSxDQUFBLEtBQUEsT0FBQSxDQUFBLEVBQUEsQ0FBQTtBQUNBLEtBUkEsRUFTQSxJQVRBLENBU0EsWUFBQTtBQUNBLDREQUFBO0FBQ0EsWUFBQSxNQUFBLE9BQUEsU0FBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxlQUFBLFNBQUEsQ0FBQSxNQUFBLENBQUEsR0FBQSxFQUFBLENBQUE7QUFDQSxlQUFBLEtBQUEsR0FBQSxTQUFBLE9BQUEsU0FBQSxDQUFBO0FBQ0E7QUFDQSxLQWZBO0FBZ0JBLEdBakJBOztBQW1CQSxTQUFBLFlBQUEsR0FBQSxVQUFBLE1BQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxXQUFBLElBQUEsR0FBQSxLQUFBO0FBQ0EsUUFBQSxXQUFBLENBQUEsRUFBQSxLQUFBLFVBQUEsQ0FBQSxJQUFBLEVBQUEsS0FDQSxJQUFBLFVBQUEsS0FBQSxPQUFBLENBQUEsU0FBQSxJQUFBLFNBQUEsQ0FBQSxFQUFBO0FBQ0Esa0JBQUEsZUFBQSxHQUNBLElBREEsQ0FDQSxnQkFBQTtBQUNBLFlBQUEsQ0FBQSxJQUFBLEVBQUE7QUFDQSxjQUFBLGNBQUEsUUFBQSxjQUFBO0FBQ0EsY0FBQSxVQUFBLEtBQUEsS0FBQSxDQUFBLFlBQUEsT0FBQSxDQUFBLEtBQUEsRUFBQSxDQUFBLENBQUEsQ0FGQSxDQUVBO0FBQ0Esa0JBQUEsQ0FBQSxJQUFBLE1BQUE7QUFDQSxzQkFBQSxPQUFBLENBQUEsQ0FBQSxLQUFBLEVBQUEsQ0FBQSxFQUFBLEtBQUEsU0FBQSxDQUFBLENBQUEsS0FBQSxPQUFBLEVBQUEsUUFBQSxDQUFBLENBQUEsQ0FBQSxDQUFBO0FBQ0EsaUJBQUEsU0FBQSxHQUFBLEtBQUEscUJBQUEsRUFBQTtBQUNBLGlCQUFBLEtBQUEsR0FBQSxTQUFBLE9BQUEsU0FBQSxDQUFBO0FBQ0EsU0FQQSxNQVFBO0FBQ0EsaUJBQUEsS0FBQSxjQUFBLENBQUEsTUFBQSxFQUFBLElBQUEsQ0FBQTtBQUNBO0FBQ0EsT0FiQSxFQWNBLElBZEEsQ0FjQSxZQUFBO0FBQUEsMENBQUEsSUFBQTtBQUFBLGNBQUE7QUFBQTs7QUFDQSxZQUFBLEtBQUEsQ0FBQSxDQUFBLEVBQUE7QUFDQSxjQUFBLE1BQUEsT0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLGlCQUFBLFNBQUEsQ0FBQSxHQUFBLEVBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQSxFQUFBLFFBQUE7QUFDQSxpQkFBQSxLQUFBLEdBQUEsU0FBQSxPQUFBLFNBQUEsQ0FBQTtBQUNBO0FBQ0EsT0FwQkE7QUFxQkE7QUFFQSxHQTNCQTs7QUE2QkEsU0FBQSxRQUFBLEdBQUEsWUFBQTtBQUNBLFdBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxHQUZBO0FBSUEsQ0FoRUE7O0FDekVBLENBQUEsWUFBQTs7QUFFQTs7QUFFQTs7QUFDQSxNQUFBLENBQUEsT0FBQSxPQUFBLEVBQUEsTUFBQSxJQUFBLEtBQUEsQ0FBQSx3QkFBQSxDQUFBOztBQUVBLE1BQUEsTUFBQSxRQUFBLE1BQUEsQ0FBQSxhQUFBLEVBQUEsRUFBQSxDQUFBOztBQUVBLE1BQUEsT0FBQSxDQUFBLFFBQUEsRUFBQSxZQUFBO0FBQ0EsUUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLE1BQUEsSUFBQSxLQUFBLENBQUEsc0JBQUEsQ0FBQTtBQUNBLFdBQUEsT0FBQSxFQUFBLENBQUEsT0FBQSxRQUFBLENBQUEsTUFBQSxDQUFBO0FBQ0EsR0FIQTs7QUFLQTtBQUNBO0FBQ0E7QUFDQSxNQUFBLFFBQUEsQ0FBQSxhQUFBLEVBQUE7QUFDQSxrQkFBQSxvQkFEQTtBQUVBLGlCQUFBLG1CQUZBO0FBR0EsbUJBQUEscUJBSEE7QUFJQSxvQkFBQSxzQkFKQTtBQUtBLHNCQUFBLHdCQUxBO0FBTUEsbUJBQUE7QUFOQSxHQUFBOztBQVNBLE1BQUEsT0FBQSxDQUFBLGlCQUFBLEVBQUEsVUFBQSxVQUFBLEVBQUEsRUFBQSxFQUFBLFdBQUEsRUFBQTtBQUNBLFFBQUEsYUFBQTtBQUNBLFdBQUEsWUFBQSxnQkFEQTtBQUVBLFdBQUEsWUFBQSxhQUZBO0FBR0EsV0FBQSxZQUFBLGNBSEE7QUFJQSxXQUFBLFlBQUE7QUFKQSxLQUFBO0FBTUEsV0FBQTtBQUNBLHFCQUFBLHVCQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFVBQUEsQ0FBQSxXQUFBLFNBQUEsTUFBQSxDQUFBLEVBQUEsUUFBQTtBQUNBLGVBQUEsR0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBO0FBQ0E7QUFKQSxLQUFBO0FBTUEsR0FiQTs7QUFlQSxNQUFBLE1BQUEsQ0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLGtCQUFBLFlBQUEsQ0FBQSxJQUFBLENBQUEsQ0FDQSxXQURBLEVBRUEsVUFBQSxTQUFBLEVBQUE7QUFDQSxhQUFBLFVBQUEsR0FBQSxDQUFBLGlCQUFBLENBQUE7QUFDQSxLQUpBLENBQUE7QUFNQSxHQVBBOztBQVNBLE1BQUEsT0FBQSxDQUFBLGFBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsVUFBQSxFQUFBLFdBQUEsRUFBQSxFQUFBLEVBQUE7O0FBRUEsYUFBQSxpQkFBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFVBQUEsT0FBQSxTQUFBLElBQUE7QUFDQSxjQUFBLE1BQUEsQ0FBQSxLQUFBLEVBQUEsRUFBQSxLQUFBLElBQUE7QUFDQSxpQkFBQSxVQUFBLENBQUEsWUFBQSxZQUFBO0FBQ0EsYUFBQSxLQUFBLElBQUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsU0FBQSxlQUFBLEdBQUEsWUFBQTtBQUNBLGFBQUEsQ0FBQSxDQUFBLFFBQUEsSUFBQTtBQUNBLEtBRkE7O0FBSUEsU0FBQSxlQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQSxVQUFBLEtBQUEsZUFBQSxNQUFBLGVBQUEsSUFBQSxFQUFBO0FBQ0EsZUFBQSxHQUFBLElBQUEsQ0FBQSxRQUFBLElBQUEsQ0FBQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGFBQUEsTUFBQSxHQUFBLENBQUEsVUFBQSxFQUFBLElBQUEsQ0FBQSxpQkFBQSxFQUFBLEtBQUEsQ0FBQSxZQUFBO0FBQ0EsZUFBQSxJQUFBO0FBQ0EsT0FGQSxDQUFBO0FBSUEsS0FyQkE7O0FBdUJBLFNBQUEsS0FBQSxHQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsYUFBQSxNQUFBLElBQUEsQ0FBQSxRQUFBLEVBQUEsV0FBQSxFQUNBLElBREEsQ0FDQSxpQkFEQSxFQUVBLEtBRkEsQ0FFQSxZQUFBO0FBQ0EsZUFBQSxHQUFBLE1BQUEsQ0FBQSxFQUFBLFNBQUEsNEJBQUEsRUFBQSxDQUFBO0FBQ0EsT0FKQSxDQUFBO0FBS0EsS0FOQTs7QUFRQSxTQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsYUFBQSxNQUFBLEdBQUEsQ0FBQSxTQUFBLEVBQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSxnQkFBQSxPQUFBO0FBQ0EsbUJBQUEsVUFBQSxDQUFBLFlBQUEsYUFBQTtBQUNBLE9BSEEsQ0FBQTtBQUlBLEtBTEE7QUFPQSxHQXJEQTs7QUF1REEsTUFBQSxPQUFBLENBQUEsU0FBQSxFQUFBLFVBQUEsVUFBQSxFQUFBLFdBQUEsRUFBQTs7QUFFQSxRQUFBLE9BQUEsSUFBQTs7QUFFQSxlQUFBLEdBQUEsQ0FBQSxZQUFBLGdCQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUEsT0FBQTtBQUNBLEtBRkE7O0FBSUEsZUFBQSxHQUFBLENBQUEsWUFBQSxjQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUEsT0FBQTtBQUNBLEtBRkE7O0FBSUEsU0FBQSxFQUFBLEdBQUEsSUFBQTtBQUNBLFNBQUEsSUFBQSxHQUFBLElBQUE7O0FBRUEsU0FBQSxNQUFBLEdBQUEsVUFBQSxTQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLEdBQUEsU0FBQTtBQUNBLFdBQUEsSUFBQSxHQUFBLElBQUE7QUFDQSxLQUhBOztBQUtBLFNBQUEsT0FBQSxHQUFBLFlBQUE7QUFDQSxXQUFBLEVBQUEsR0FBQSxJQUFBO0FBQ0EsV0FBQSxJQUFBLEdBQUEsSUFBQTtBQUNBLEtBSEE7QUFLQSxHQXpCQTtBQTJCQSxDQXBJQTs7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGlCQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxTQUFBLEdBREE7QUFFQSxpQkFBQTtBQUZBLEdBQUE7QUFJQSxDQUxBOztBQ0FBLElBQUEsT0FBQSxDQUFBLE9BQUEsRUFBQSxVQUFBLEtBQUEsRUFBQSxVQUFBLEVBQUEsRUFBQSxFQUFBO0FBQ0EsTUFBQSxlQUFBLEVBQUE7O0FBRUEsZUFBQSxpQkFBQSxHQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsUUFBQSxhQUFBLEVBQUE7QUFDQSxTQUFBLElBQUEsU0FBQSxJQUFBLE9BQUEsRUFBQTtBQUNBLGlCQUFBLElBQUEsQ0FBQSxNQUFBLElBQUEsQ0FBQSxrQkFBQSxTQUFBLEVBQUEsRUFBQSxVQUFBLFFBQUEsU0FBQSxFQUFBLENBQUEsQ0FBQSxFQUFBLENBQUE7QUFDQTtBQUNBLFdBQUEsV0FBQSxJQUFBO0FBQ0EsV0FBQSxHQUFBLEdBQUEsQ0FBQSxVQUFBLENBQUE7QUFDQSxHQVBBOztBQVNBLFNBQUEsWUFBQTtBQUNBLENBYkE7O0FBZ0JBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBOztBQUVBLGlCQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxTQUFBLFFBREE7QUFFQSxpQkFBQSxxQkFGQTtBQUdBLGdCQUFBO0FBSEEsR0FBQTtBQU1BLENBUkE7O0FBVUEsSUFBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUEsVUFBQSxFQUFBLEtBQUEsRUFBQSxhQUFBLEVBQUE7O0FBRUEsU0FBQSxLQUFBLEdBQUEsRUFBQTtBQUNBLFNBQUEsS0FBQSxHQUFBLElBQUE7O0FBRUEsU0FBQSxTQUFBLEdBQUEsVUFBQSxTQUFBLEVBQUE7O0FBRUEsV0FBQSxLQUFBLEdBQUEsSUFBQTs7QUFFQSxnQkFBQSxLQUFBLENBQUEsU0FBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsVUFBQSxXQUFBLElBQUEsRUFBQTtBQUNBLGVBQUEsTUFBQSxpQkFBQSxDQUFBLFdBQUEsSUFBQSxDQUFBO0FBQ0E7QUFDQSxLQUxBLEVBTUEsSUFOQSxDQU1BLFlBQUE7QUFDQSxhQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsS0FSQSxFQVNBLEtBVEEsQ0FTQSxZQUFBO0FBQ0EsYUFBQSxLQUFBLEdBQUEsNEJBQUE7QUFDQSxLQVhBO0FBWUEsR0FoQkE7QUFrQkEsQ0F2QkE7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QUFBQSxHQVZBOztBQVlBLFNBQUEsV0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsUUFBQSxlQUFBLE1BQUEsWUFBQSxDQURBLENBQ0E7QUFDQSxRQUFBLGVBQUEsTUFBQSxZQUFBLENBRkEsQ0FFQTs7QUFFQSxVQUFBLHFCQUFBLENBQUEsYUFBQSxFQUFBLEVBQUEsWUFBQSxFQUNBLElBREEsQ0FDQSxZQUFBO0FBQ0EsYUFBQSxRQUFBLEdBQUEsQ0FBQSxhQUFBLEdBQUEsQ0FBQTtBQUFBLGVBQUEsTUFBQSxrQkFBQSxDQUFBLFlBQUEsRUFBQSxFQUFBLFdBQUEsQ0FBQTtBQUFBLE9BQUEsQ0FBQSxDQUFBO0FBQ0EsS0FIQSxFQUlBLElBSkEsQ0FJQSxtQkFBQTtBQUNBO0FBQ0EsVUFBQSxrQkFBQTtBQUNBLGNBQUEsTUFBQSxDQUFBO0FBQUEsZUFBQSxDQUFBLE9BQUEsU0FBQTtBQUFBLE9BQUEsRUFBQSxNQUFBLEdBQUEsQ0FBQSxHQUFBLFlBQUEsS0FBQSxHQUFBLFlBQUEsSUFBQTtBQUNBLGFBQUEsTUFBQSxxQkFBQSxDQUFBLGFBQUEsRUFBQSxFQUFBLEVBQUEsV0FBQSxTQUFBLEVBQUEsQ0FBQTtBQUNBLEtBVEEsRUFVQSxJQVZBLENBVUE7QUFBQSxhQUFBLE9BQUEsRUFBQSxDQUFBLGNBQUEsQ0FBQTtBQUFBLEtBVkEsRUFXQSxLQVhBLENBV0E7QUFBQSxhQUFBLFFBQUEsS0FBQSxDQUFBLEtBQUEsQ0FBQTtBQUFBLEtBWEE7QUFZQSxHQWhCQTtBQWlCQSxDQWhDQTs7QUNKQSxJQUFBLFVBQUEsQ0FBQSxXQUFBLEVBQUEsWUFBQTtBQUNBO0FBQ0EsQ0FGQTs7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGlCQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxTQUFBLFFBREE7QUFFQSxpQkFBQSwwQkFGQTtBQUdBLGFBQUE7QUFDQSxpQkFBQSxtQkFBQSxXQUFBLEVBQUEsVUFBQSxFQUFBLE1BQUEsRUFBQTtBQUNBLGVBQUEsWUFBQSxlQUFBLEdBQ0EsSUFEQSxDQUNBLGdCQUFBO0FBQ0EsY0FBQSxDQUFBLEtBQUEsT0FBQSxFQUFBLE9BQUEsRUFBQSxDQUFBLE1BQUEsRUFBQSxLQUNBLFdBQUEsT0FBQSxHQUFBLElBQUE7QUFDQSxTQUpBLENBQUE7QUFLQTtBQVBBLEtBSEE7QUFZQSxnQkFBQTtBQVpBLEdBQUEsRUFjQSxLQWRBLENBY0EsYUFkQSxFQWNBO0FBQ0EsU0FBQSxRQURBO0FBRUEsaUJBQUEsaUNBRkE7QUFHQSxnQkFBQTtBQUhBLEdBZEEsRUFtQkEsS0FuQkEsQ0FtQkEsa0JBbkJBLEVBbUJBO0FBQ0EsU0FBQSxnQkFEQTtBQUVBLGlCQUFBLHVDQUZBO0FBR0EsZ0JBQUE7QUFIQSxHQW5CQSxFQXdCQSxLQXhCQSxDQXdCQSxnQkF4QkEsRUF3QkE7QUFDQSxTQUFBLFdBREE7QUFFQSxpQkFBQSx1Q0FGQTtBQUdBLGdCQUFBO0FBSEEsR0F4QkEsRUE2QkEsS0E3QkEsQ0E2QkEscUJBN0JBLEVBNkJBO0FBQ0EsU0FBQSxzQkFEQTtBQUVBLGlCQUFBLDZDQUZBO0FBR0EsZ0JBQUE7QUFIQSxHQTdCQSxFQWtDQSxLQWxDQSxDQWtDQSxjQWxDQSxFQWtDQTtBQUNBLFNBQUEsU0FEQTtBQUVBLGlCQUFBLG1DQUZBO0FBR0EsZ0JBQUEsaUJBSEE7QUFJQSxhQUFBO0FBQ0EsY0FBQSxnQkFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsb0JBQUEsR0FDQSxJQURBLENBQ0Esa0JBQUE7QUFDQSxpQkFBQSxNQUFBO0FBQ0EsU0FIQSxFQUlBLEtBSkEsQ0FJQTtBQUFBLGlCQUFBLFFBQUEsS0FBQSxDQUFBLEtBQUEsQ0FBQTtBQUFBLFNBSkEsQ0FBQTtBQUtBO0FBUEE7QUFKQSxHQWxDQSxFQWdEQSxLQWhEQSxDQWdEQSxtQkFoREEsRUFnREE7QUFDQSxTQUFBLGtCQURBO0FBRUEsaUJBQUEseUNBRkE7QUFHQSxnQkFBQTtBQUhBLEdBaERBO0FBc0RBLENBdkRBOztBQ0FBOztBQUVBLElBQUEsVUFBQSxDQUFBLG1CQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsT0FBQSxFQUFBLFVBQUEsRUFBQTs7QUFFQSxhQUFBLEdBQUEsQ0FBQSxXQUFBLEVBQUEsVUFBQSxDQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsV0FBQSxNQUFBLEdBQUEsSUFBQTtBQUNBLEdBRkE7O0FBSUEsVUFBQSxNQUFBLEdBQ0EsSUFEQSxDQUNBLG9CQUFBO0FBQ0EsV0FBQSxRQUFBLEdBQUEsUUFBQTtBQUNBLEdBSEEsRUFJQSxLQUpBLENBSUEsaUJBQUE7QUFDQSxZQUFBLEdBQUEsQ0FBQSxLQUFBO0FBQ0EsR0FOQTtBQU9BLENBYkE7O0FBZ0JBLElBQUEsVUFBQSxDQUFBLHdCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQSxZQUFBLEVBQUE7QUFDQSxNQUFBLFlBQUEsYUFBQSxTQUFBOztBQUVBLFVBQUEsTUFBQSxDQUFBLFNBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxXQUFBLE9BQUEsT0FBQSxHQUFBLE9BQUE7QUFBQSxHQURBLEVBRUEsS0FGQSxDQUVBO0FBQUEsV0FBQSxRQUFBLEtBQUEsQ0FBQSxLQUFBLENBQUE7QUFBQSxHQUZBOztBQUlBLFNBQUEsV0FBQSxHQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLENBQUEsU0FBQSxFQUFBLFFBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxhQUFBLE9BQUEsRUFBQSxDQUFBLGdCQUFBLENBQUE7QUFBQSxLQURBO0FBRUEsR0FIQTtBQUlBLENBWEE7O0FDbEJBLElBQUEsVUFBQSxDQUFBLGdCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsSUFBQSxFQUFBLFVBQUEsRUFBQTs7QUFFQSxhQUFBLEdBQUEsQ0FBQSxXQUFBLEVBQUEsVUFBQSxDQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsV0FBQSxNQUFBLEdBQUEsSUFBQTtBQUNBLEdBRkE7QUFHQTtBQUNBLE9BQUEsTUFBQSxHQUNBLElBREEsQ0FDQTtBQUFBLFdBQUEsT0FBQSxLQUFBLEdBQUEsS0FBQTtBQUFBLEdBREEsRUFFQSxLQUZBLENBRUE7QUFBQSxXQUFBLFFBQUEsS0FBQSxDQUFBLEtBQUEsQ0FBQTtBQUFBLEdBRkE7QUFHQSxDQVRBOztBQVdBLElBQUEsVUFBQSxDQUFBLHNCQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsSUFBQSxFQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxNQUFBLFNBQUEsU0FBQSxhQUFBLE1BQUEsQ0FBQTs7QUFFQTtBQUNBLE9BQUEsTUFBQSxDQUFBLE1BQUEsRUFDQSxJQURBLENBQ0EsZ0JBQUE7QUFDQSxXQUFBLElBQUEsR0FBQSxJQUFBO0FBQ0EsR0FIQSxFQUlBLEtBSkEsQ0FJQTtBQUFBLFdBQUEsUUFBQSxLQUFBLENBQUEsS0FBQSxDQUFBO0FBQUEsR0FKQTs7QUFNQSxTQUFBLFdBQUEsR0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLFNBQUEsT0FBQSxDQUFBLE1BQUEsRUFBQSxRQUFBLEVBQ0EsSUFEQSxDQUNBO0FBQUEsYUFBQSxPQUFBLEVBQUEsQ0FBQSxhQUFBLENBQUE7QUFBQSxLQURBLEVBRUEsS0FGQSxDQUVBO0FBQUEsYUFBQSxRQUFBLEtBQUEsQ0FBQSxLQUFBLENBQUE7QUFBQSxLQUZBO0FBR0EsR0FKQTtBQU1BLENBaEJBOztBQ1hBOztBQUVBLElBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLFNBQUE7QUFDQSxvQkFBQSwwQkFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLENBQUEsbUJBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxlQUFBLElBQUEsSUFBQTtBQUFBLE9BREEsQ0FBQTtBQUVBLEtBSkE7QUFLQSxzQkFBQSwwQkFBQSxXQUFBLEVBQUEsSUFBQSxFQUFBO0FBQ0EsVUFBQSxJQUFBLEVBQUE7QUFDQSxlQUFBLE1BQUEsSUFBQSxDQUFBLG1CQUFBLEVBQUEsV0FBQSxFQUNBLElBREEsQ0FDQTtBQUFBLGlCQUFBLElBQUEsSUFBQTtBQUFBLFNBREEsQ0FBQTtBQUVBLE9BSEEsTUFHQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsY0FBQSxFQUFBLFdBQUEsRUFDQSxJ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QURBLENBQ0E7QUFBQSxlQUFBLElBQUEsSUFBQTtBQUFBLE9BREEsQ0FBQTtBQUVBLEtBdkNBOztBQXlDQSx3QkFBQSw0QkFBQSxZQUFBLEVBQUE7QUFDQSxhQUFBLE1BQUEsSUFBQSxDQUFBLHFCQUFBLEVBQUEsWUFBQSxFQUNBLElBREEsQ0FDQTtBQUFBLGVBQUEsSUFBQSxJQUFBO0FBQUEsT0FEQSxDQUFBO0FBRUE7QUE1Q0EsR0FBQTtBQThDQSxDQS9DQTs7QUNGQTs7QUFFQSxJQUFBLE9BQUEsQ0FBQSxTQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsTUFBQSxpQkFBQSxFQUFBOztBQUVBLGlCQUFBLEdBQUEsR0FBQSxlQUFBOztBQUVBLGlCQUFBLE1BQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLFFBQUEsQ0FBQSxLQUFBLEVBQUEsUUFBQSxFQUFBO0FBQ0EsV0FBQSxNQUFBLEdBQUEsQ0FBQSxlQUFBLEdBQUEsR0FBQSxLQUFBLEVBQ0EsSUFEQSxDQUNBO0FBQUEsYUFBQSxJQUFBLElBQUE7QUFBQSxLQURBLENBQUE7QUFFQSxHQUpBOztBQU1BLGlCQUFBLE1BQUEsR0FBQSxVQUFBLEVBQUEsRUFBQTtBQUNBLFdBQUEsTUFBQSxHQUFBLENBQUEsZUFBQSxHQUFBLEdBQUEsR0FBQSxHQUFBLEVBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxhQUFBLElBQUEsSUFBQTtBQUFBLEtBREEsQ0FBQTtBQUVBLEdBSEE7O0FBS0EsaUJBQUEsT0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLElBQUEsRUFBQTtBQUNBLFdBQUEsTUFBQSxHQUFBLENBQUEsZUFBQSxHQUFBLEdBQUEsR0FBQSxHQUFBLEVBQUEsRUFBQSxJQUFBLEVBQ0EsSUFEQSxDQUNBO0FBQUEsYUFBQSxJQUFBLElBQUE7QUFBQSxLQURBLENBQUE7QUFFQSxHQUhBOztBQUtBLFNBQUEsY0FBQTtBQUNBLENBdkJBOztBQ0ZBLElBQUEsT0FBQSxDQUFBLGVBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLFNBQUE7QUFDQSxlQUFBLG1CQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUE7QUFDQSxhQUFBLE1BQUEsSUFBQSxDQUFBLGtCQUFBLFNBQUEsRUFBQSxFQUFBLE9BQUEsT0FBQSxLQUFBLEVBQUEsYUFBQSxPQUFBLFdBQUEsRUFBQSxDQUFBO0FBQ0EsS0FIQTtBQUlBLGdCQUFBLG9CQUFBLFNBQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLENBQUEsa0JBQUEsU0FBQSxFQUNBLElBREEsQ0FDQTtBQUFBLGVBQUEsSUFBQSxJQUFBO0FBQUEsT0FEQSxDQUFBO0FBRUE7QUFQQSxHQUFBO0FBU0EsQ0FWQTs7QUNBQTs7QUFFQSxJQUFBLE9BQUEsQ0FBQSxNQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxTQUFBO0FBQ0EsWUFBQSxnQkFBQSxVQUFBLEVBQUE7QUFDQSxhQUFBLE1BQUEsSUFBQSxDQUFBLFlBQUEsRUFBQSxVQUFBLEVBQ0EsSUFEQSxDQUNBO0FBQUEsZUFBQSxJQUFBLElBQUE7QUFBQSxPQURBLENBQUE7QUFFQSxLQUpBOztBQU1BLFlBQUEsa0JBQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxDQUFBLFlBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxlQUFBLElBQUEsSUFBQTtBQUFBLE9BREEsQ0FBQTtBQUVBLEtBVEE7O0FBV0EsWUFBQSxnQkFBQSxFQUFBLEVBQUE7QUFDQSxhQUFBLE1BQUEsR0FBQSxDQUFBLGdCQUFBLEVBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxlQUFBLElBQUEsSUFBQTtBQUFBLE9BREEsQ0FBQTtBQUVBLEtBZEE7O0FBZ0JBLGFBQUEsaUJBQUEsRUFBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGFBQUEsTUFBQSxHQUFBLENBQUEsZ0JBQUEsRUFBQSxFQUFBLElBQUEsRUFDQSxJQURBLENBQ0E7QUFBQSxlQUFBLElBQUEsSUFBQTtBQUFBLE9BREEsQ0FBQTtBQUVBO0FBbkJBLEdBQUE7QUFxQkEsQ0F0QkE7O0FDRkE7O0FBRUEsSUFBQSxPQUFBLENBQUEsU0FBQSxFQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0Es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a0JBQUEsQ0FBQSxLQUFBLFFBQUE7QUFDQSxzQkFBQSxPQUFBLENBQUEsQ0FBQSxRQUFBLEVBQUEsQ0FBQSxFQUFBLEtBQUEsU0FBQSxDQUFBLENBQUEsT0FBQSxFQUFBLFFBQUEsQ0FBQSxDQUFBLENBQUEsQ0FBQTtBQUNBLFNBSkEsTUFJQTtBQUNBLHNCQUFBLE9BQUEsQ0FBQSxDQUFBLFFBQUEsRUFBQSxDQUFBLEVBQUEsS0FBQSxTQUFBLENBQUEsQ0FBQSxPQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7QUFDQTtBQUNBLE9BVEEsTUFVQTtBQUNBLGVBQUEsTUFBQSxJQUFBLENBQUEsa0JBQUEsUUFBQSxFQUFBLEVBQUEsRUFBQSxVQUFBLFFBQUEsRUFBQSxDQUFBO0FBQ0E7QUFDQSxLQWZBLEVBZ0JBLElBaEJBLENBZ0JBLFlBQUE7QUFBQSx5Q0FBQSxJQUFBO0FBQUEsWUFBQTtBQUFBOztBQUNBLFVBQUEsS0FBQSxDQUFBLENBQUEsRUFBQSxPQUFBLEtBQUEsQ0FBQSxFQUFBLElBQUE7QUFFQSxLQW5CQSxDQUFBO0FBb0JBLEdBdkJBOztBQXlCQSxTQUFBLGtCQUFBO0FBRUEsQ0EvQkE7O0FDQUEsSUFBQSxVQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxRQUFBLEVBQUEsT0FBQSxFQUFBLE9BQUEsRUFBQTtBQUNBLFNBQUEsUUFBQSxHQUFBLFFBQUE7QUFDQSxTQUFBLFNBQUEsR0FBQSxFQUFBOztBQUVBLFNBQUEsV0FBQSxHQUFBLFVBQUEsUUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLFdBQUEsU0FBQSxDQUFBLFFBQUEsSUFBQSxLQUFBO0FBQ0EsUUFBQSxhQUFBLFFBQUEsY0FBQSxDQUFBLE9BQUEsU0FBQSxDQUFBO0FBQ0EsWUFBQSxNQUFBLENBQUEsVUFBQSxFQUNBLElBREEsQ0FDQSxvQkFBQTtBQUNBLGFBQUEsUUFBQSxHQUFBLFFBQUE7QUFDQSxLQUhBO0FBSUEsR0FQQTs7QUFTQSxTQUFBLGdCQUFBLEdBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxXQUFBLE9BQUEsU0FBQSxDQUFBLFFBQUEsQ0FBQTtBQUNBLFFBQUEsYUFBQSxRQUFBLGNBQUEsQ0FBQSxPQUFBLFNBQUEsQ0FBQTtBQUNBLFlBQUEsTUFBQSxDQUFBLFVBQUEsRUFDQSxJQURBLENBQ0Esb0JBQUE7QUFDQSxhQUFBLFFBQUEsR0FBQSxRQUFBO0FBQ0EsS0FIQTtBQUlBLEdBUEE7O0FBU0EsU0FBQSxZQUFBLEdBQUEsVUFBQSxRQUFBLEVBQUEsS0FBQSxFQUFBLFFBQUEsRUFBQTtBQUNBLFFBQUEsT0FBQSxRQUFBLENBQUEsRUFBQTtBQUNBLGFBQUEsV0FBQSxDQUFBLFFBQUEsRUFBQSxLQUFBO0FBQ0EsS0FGQSxNQUVBO0FBQ0EsYUFBQSxnQkFBQSxDQUFBLFFBQUE7QUFDQTtBQUNBLEdBTkE7QUFRQSxDQTlCQTs7QUNBQSxJQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGlCQUFBLEtBQUEsQ0FBQSxVQUFBLEVBQUE7QUFDQSxTQUFBLFdBREE7QUFFQSxpQkFBQSxtQ0FGQTtBQUdBLGdCQUFBLGlCQUhBO0FBSUEsYUFBQTtBQUNBLGdCQUFBLGtCQUFBLE9BQUEsRUFBQTtBQUNBLGVBQUEsUUFBQSxNQUFBLEVBQUE7QUFDQTtBQUhBO0FBSkEsR0FBQTtBQVVBLENBWEE7O0FDQUEsSUFBQSxVQUFBLENBQUEsb0JBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxTQUFBLEVBQUEsT0FBQSxFQUFBLFVBQUEsRUFBQTtBQUNBLGFBQUEsU0FBQSxHQUFBLFNBQUE7QUFDQSxDQUZBOztBQ0FBLElBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0EsaUJBQUEsS0FBQSxDQUFBLG1CQUFBLEVBQUE7QUFDQSxTQUFBLFlBREE7QUFFQSxpQkFBQSx1Q0FGQTtBQUdBLGdCQUFBLG9CQUhBO0FBSUEsYUFBQTtBQUNBLGlCQUFBLG1CQUFBLE9BQUEsRUFBQTtBQUNBLGVBQUEsUUFBQSxjQUFBLEVBQUE7QUFDQTtBQUhBO0FBSkEsR0FBQTtBQVVBLENBWEE7O0FDQUEsSUFBQSxVQUFBLENBQUEsbUJBQUEsRUFB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QUFBO0FBQ0EsU0FBQTtBQUNBLGNBQUEsR0FEQTtBQUVBLGlCQUFBLHdEQUZBO0FBR0EsV0FBQTtBQUNBLGVBQUE7QUFEQSxLQUhBO0FBTUEsVUFBQSxjQUFBLEtBQUEsRUFBQSxJQUFBLEVBQUEsS0FBQSxFQUFBO0FBQ0EsWUFBQSxLQUFBLEdBQUEsS0FBQTtBQUNBLFlBQUEsVUFBQSxHQUFBLENBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQSxDQUFBLEVBQUEsQ0FBQSxFQUFBLENBQUEsRUFBQSxDQUFBLEVBQUEsRUFBQSxDQUFBO0FBQ0EsWUFBQSxRQUFBLEdBQUEsTUFBQSxVQUFBLENBQUEsQ0FBQSxDQUFBO0FBQ0EsWUFBQSxTQUFBLEdBQUEsVUFBQSxPQUFBLEVBQUE7QUFDQSxjQUFBLEtBQUEsR0FBQSxJQUFBO0FBQ0EsMkJBQUEsVUFBQSxDQUFBLE9BQUEsRUFBQSxNQUFBLFFBQUEsRUFDQSxJQURBLENBQ0EsWUFBQTtBQUNBLGlCQUFBLEVBQUEsQ0FBQSxNQUFBO0FBQ0EsU0FIQTtBQUlBLE9BTkE7QUFPQTtBQWpCQSxHQUFBO0FBbUJBLENBcEJBOztBQ0ZBOztBQUVBLElBQUEsU0FBQSxDQUFBLGFBQUEsRUFBQSxZQUFBO0FBQ0EsU0FBQTtBQUNBLGNBQUEsR0FEQTtBQUVBLGlCQUFBLGlEQUZBO0FBR0EsV0FBQTtBQUNBLGVBQUE7QUFEQSxLQUhBO0FBTUEsVUFBQSxjQUFBLEtBQUEsRUFBQSxJQUFBLEVBQUEsS0FBQSxFQUFBO0FBQ0EsWUFBQSxPQUFBLENBQUEsV0FBQSxHQUFBLE1BQUEsT0FBQSxDQUFBLFdBQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQSxFQUFBLEdBQUEsQ0FBQTtBQUNBO0FBUkEsR0FBQTtBQVVBLENBWEEiLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcbndpbmRvdy5hcHAgPSBhbmd1bGFyLm1vZHVsZSgnRnVsbHN0YWNrR2VuZXJhdGVkQXBwJywgWydmc2FQcmVCdWlsdCcsICd1aS5yb3V0ZXInLCAndWkuYm9vdHN0cmFwJywgJ25nQW5pbWF0ZSddKTtcblxuYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHVybFJvdXRlclByb3ZpZGVyLCAkbG9jYXRpb25Qcm92aWRlcikge1xuICAgIC8vIFRoaXMgdHVybnMgb2ZmIGhhc2hiYW5nIHVybHMgKC8jYWJvdXQpIGFuZCBjaGFuZ2VzIGl0IHRvIHNvbWV0aGluZyBub3JtYWwgKC9hYm91dClcbiAgICAkbG9jYXRpb25Qcm92aWRlci5odG1sNU1vZGUodHJ1ZSk7XG4gICAgLy8gSWYgd2UgZ28gdG8gYSBVUkwgdGhhdCB1aS1yb3V0ZXIgZG9lc24ndCBoYXZlIHJlZ2lzdGVyZWQsIGdvIHRvIHRoZSBcIi9cIiB1cmwuXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZSgnLycpO1xuICAgIC8vIFRyaWdnZXIgcGFnZSByZWZyZXNoIHdoZW4gYWNjZXNzaW5nIGFuIE9BdXRoIHJvdXRlXG4gICAgJHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hdXRoLzpwcm92aWRlcicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLnJlbG9hZCgpO1xuICAgIH0pO1xufSk7XG5cbi8vIFRoaXMgYXBwLnJ1biBpcyBmb3IgY29udHJvbGxpbmcgYWNjZXNzIHRvIHNwZWNpZmljIHN0YXRlcy5cbmFwcC5ydW4oZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgIC8vIFRoZSBnaXZlbiBzdGF0ZSByZXF1aXJlcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgdmFyIGRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGggPSBmdW5jdGlvbiAoc3RhdGUpIHtcbiAgICAgICAgcmV0dXJuIHN0YXRlLmRhdGEgJiYgc3RhdGUuZGF0YS5hdXRoZW50aWNhdGU7XG4gICAgfTtcblxuICAgIC8vICRzdGF0ZUNoYW5nZVN0YXJ0IGlzIGFuIGV2ZW50IGZpcmVkXG4gICAgLy8gd2hlbmV2ZXIgdGhlIHByb2Nlc3Mgb2YgY2hhbmdpbmcgYSBzdGF0ZSBiZWdpbnMuXG4gICAgJHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlLCB0b1BhcmFtcykge1xuXG4gICAgICAgIGlmICghZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCh0b1N0YXRlKSkge1xuICAgICAgICAgICAgLy8gVGhlIGRlc3RpbmF0aW9uIHN0YXRlIGRvZXMgbm90IHJlcXVpcmUgYXV0aGVudGljYXRpb25cbiAgICAgICAgICAgIC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkpIHtcbiAgICAgICAgICAgIC8vIFRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQuXG4gICAgICAgICAgICAvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ2FuY2VsIG5hdmlnYXRpbmcgdG8gbmV3IHN0YXRlLlxuICAgICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuXG4gICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgIC8vIElmIGEgdXNlciBpcyByZXRyaWV2ZWQsIHRoZW4gcmVuYXZpZ2F0ZSB0byB0aGUgZGVzdGluYXRpb25cbiAgICAgICAgICAgIC8vICh0aGUgc2Vjb25kIHRpbWUsIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpIHdpbGwgd29yaylcbiAgICAgICAgICAgIC8vIG90aGVyd2lzZSwgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4sIGdvIHRvIFwibG9naW5cIiBzdGF0ZS5cbiAgICAgICAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgJHN0YXRlLmdvKHRvU3RhdGUubmFtZSwgdG9QYXJhbXMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2xvZ2luJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuXG4gICAgfSk7XG5cbn0pO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuY29udHJvbGxlcignQ2hlY2tvdXRDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBjYXJ0SXRlbXMsIEF1dGhTZXJ2aWNlLCBDYXJkLCBDYXJ0LCBPcmRlciwgbWUsICRyb290U2NvcGUsIEFkZHJlc3MpIHtcblxuICAgICRzY29wZS5jYXJ0SXRlbXMgPSBjYXJ0SXRlbXM7XG4gICAgJHNjb3BlLm1lID0gbWU7XG5cbiAgICBpZiAoJHNjb3BlLm1lKSBDYXJkLmdldE15Q2FyZHMoKS50aGVuKGNhcmRzID0+IHsgJHJvb3RTY29wZS5jYXJkcyA9IGNhcmRzIH0pO1xuICAgIGVsc2UgJHJvb3RTY29wZS5jYXJkcyA9IFtdO1xuXG4gICAgaWYgKCRzY29wZS5tZSkgQWRkcmVzcy5nZXRNeUFkZHJlc3NlcygpLnRoZW4oYWRkcmVzc2VzID0+IHsgJHJvb3RTY29wZS5hZGRyZXNzZXMgPSBhZGRyZXNzZXMgfSk7XG4gICAgZWxzZSAkcm9vdFNjb3BlLmFkZHJlc3NlcyA9IFtdO1xuXG4gICAgJHNjb3BlLm5ld09yZGVyID0ge1xuICAgICAgICBvcmRlclN1bW1hcnk6IHtcbiAgICAgICAgICAgIHByaWNlVG90YWw6IGNhcnRJdGVtcy5yZWR1Y2UoZnVuY3Rpb24oc3VtLCBpdGVtKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIE1hdGgucm91bmQoc3VtICsgKGl0ZW0ucHJvZHVjdC5wcmljZSkgKiBpdGVtLnF1YW50aXR5KTtcbiAgICAgICAgICAgIH0sIDApXG4gICAgICAgIH0sXG4gICAgICAgIG9yZGVyRGV0YWlsczoge1xuICAgICAgICAgICAgaXRlbXM6ICRzY29wZS5jYXJ0SXRlbXNcbiAgICAgICAgfVxuICAgIH07XG5cbiAgICBmdW5jdGlvbiByZXNwb25zZUhhbmRsZXIoc3RhdHVzLCByZXNwb25zZSkge1xuICAgICAgICBpZiAocmVzcG9uc2UuZXJyb3IpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IocmVzcG9uc2UuZXJyb3IubWVzc2FnZSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YXIgY2hhcmdlRGV0YWlscyA9IHt9O1xuICAgICAgICAgICAgY2hhcmdlRGV0YWlscy5zb3VyY2UgPSByZXNwb25zZS5pZDtcbiAgICAgICAgICAgIGNoYXJnZURldGFpbHMuc3RyaXBlVG9rZW4gPSByZXNwb25zZS5pZDtcbiAgICAgICAgICAgIGNoYXJnZURldGFpbHMudXNlcklkID0gJHNjb3BlLnVzZXIuaWQ7XG4gICAgICAgICAgICBjaGFyZ2VEZXRhaWxzLmFtb3VudCA9ICRzY29wZS5uZXdPcmRlci5vcmRlclN1bW1hcnkucHJpY2VUb3RhbDtcbiAgICAgICAgICAgIFxuICAgICAgICAgICAgT3JkZXIuc2VuZFRvU3RyaXBlKGNoYXJnZURldGFpbHMpXG4gICAgICAgICAgICAudGhlbigoKSA9PiBPcmRlci5jcmVhdGVPcmRlclN1bW1hcnkob3JkZXIub3JkZXJTdW1tYXJ5KSlcbiAgICAgICAgICAgIC50aGVuKG9yZGVyU3VtbWFyeSA9PiB7XG4gICAgICAgICAgICAgICAgb3JkZXIub3JkZXJEZXRhaWxzLm9yZGVyU3VtbWFyeUlkID0gb3JkZXJTdW1tYXJ5LmlkO1xuICAgICAgICAgICAgICAgIG9yZGVyLm9yZGVyRGV0YWlscy5pdGVtcy5mb3JFYWNoKGl0ZW0gPT4ge1xuICAgICAgICAgICAgICAgICAgICBpdGVtLnB1cmNoYXNlQ29zdCA9IGl0ZW0ucHJvZHVjdC5wcmljZSAqIGl0ZW0ucXVhbnRpdHk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIE9yZGVyLmNyZWF0ZU9yZGVyRGV0YWlscyhvcmRlci5vcmRlckRldGFpbHMpO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC50aGVuKCgpID0+IHtcblxuICAgICAgICAgICAgICAgICRzY29wZS5jYXJ0SXRlbXMgPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAodXNlcikge1xuICAgICAgICAgICAgICAgICAgICBDYXJ0LmNsZWFyQ2FydFVzZXIoKVxuICAgICAgICAgICAgICAgIH0gZWxzZSB7IENhcnQuY2xlYXJDYXJ0VmlzaXRvcigpIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICAkc2NvcGUuY3JlYXRlT3JkZXIgPSBmdW5jdGlvbihvcmRlcikge1xuICAgICAgICBvcmRlci5vcmRlclN1bW1hcnkuY2FyZElkID0gb3JkZXIuY2FyZC5pZDtcblxuICAgICAgICB2YXIgJGZvcm0gPSB7XG4gICAgICAgICAgICAnbnVtYmVyJzogb3JkZXIuY2FyZC5udW1iZXIsXG4gICAgICAgICAgICAnZXhwX21vbnRoJzogb3JkZXIuY2FyZC5leHBfbW9udGgsXG4gICAgICAgICAgICAnZXhwX3llYXInOiBvcmRlci5jYXJkLmV4cF95ZWFyLFxuICAgICAgICAgICAgJ2N2Yyc6IG9yZGVyLmNhcmQuY3ZjXG4gICAgICAgIH1cblxuICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKVxuICAgICAgICAgICAgLnRoZW4odXNlckxvZ2dlZEluID0+IHtcbiAgICAgICAgICAgICAgICAkc2NvcGUudXNlciA9IHVzZXJMb2dnZWRJbjtcbiAgICAgICAgICAgICAgICByZXR1cm4gU3RyaXBlLmNhcmQuY3JlYXRlVG9rZW4oJGZvcm0sIHJlc3BvbnNlSGFuZGxlcilcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAuY2F0Y2goY29uc29sZS5sb2cuYmluZChjb25zb2xlKSk7XG4gICAgfVxufSk7XG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnY2hlY2tvdXQnLCB7XG4gICAgICAgIHVybDogJy9jaGVja291dCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY2hlY2tvdXQvY2hlY2tvdXQuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdDaGVja291dEN0cmwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBjYXJ0SXRlbXM6IGZ1bmN0aW9uKENhcnQsIEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpXG4gICAgICAgICAgICAgICAgICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHVzZXIpIHJldHVybiBDYXJ0LmZldGNoQ2FydEl0ZW1zKClcbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgcmV0dXJuIENhcnQuZmV0Y2hOb3RMb2dnZWRJbkl0ZW1zKClcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oY2FydEl0ZW1zID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBjYXJ0SXRlbXMubWFwKGZ1bmN0aW9uKGNhcnRJdGVtKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FydEl0ZW0ucHJvZHVjdC5wcmljZSA9IGNhcnRJdGVtLnByb2R1Y3QucHJpY2UgLyAxMDA7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNhcnRJdGVtO1xuICAgICAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgbWU6IGZ1bmN0aW9uKEF1dGhTZXJ2aWNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSlcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0NhcnQnLCBmdW5jdGlvbiAoJGh0dHAsIEF1dGhTZXJ2aWNlLCAkcm9vdFNjb3BlLCAkc3RhdGUsICR3aW5kb3cpIHtcbiAgdmFyIENhcnRGYWN0b3J5ID0ge307XG5cbiAgdmFyIGNhcnRVcmwgPSAnL2FwaS9tZS9jYXJ0J1xuXG4gIENhcnRGYWN0b3J5LmZldGNoQ2FydEl0ZW1zID0gZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKVxuICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgaWYgKHVzZXIpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldChjYXJ0VXJsKVxuICAgICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG5cbiAgICAgICAgcmV0dXJuICRyb290U2NvcGUuY2FydDtcbiAgICAgIH1cbiAgICB9KVxuICB9XG5cbiAgQ2FydEZhY3RvcnkucmVtb3ZlSXRlbSA9IGZ1bmN0aW9uIChpZCkge1xuICAgIHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvbWUvY2FydC8nICsgaWQpXG4gIH1cblxuICBDYXJ0RmFjdG9yeS51cGRhdGVRdWFudGl0eSA9IGZ1bmN0aW9uIChuZXdOdW0sIGl0ZW0pIHtcbiAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL21lL2NhcnQvJyArIGl0ZW0ucHJvZHVjdC5pZCwge3F1YW50aXR5OiBuZXdOdW19KVxuICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gIH1cblxuICBDYXJ0RmFjdG9yeS5jbGVhckNhcnRVc2VyID0gZnVuY3Rpb24odXNlcklkKXtcbiAgICByZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL21lL2NhcnQvJylcbiAgfVxuXG4gIENhcnRGYWN0b3J5LmNsZWFyQ2FydFZpc2l0b3IgPSBmdW5jdGlvbigpe1xuICAgIHJldHVybiAkd2luZG93LnNlc3Npb25TdG9yYWdlLmNsZWFyKCk7XG4gIH1cblxuICBDYXJ0RmFjdG9yeS5mZXRjaE5vdExvZ2dlZEluSXRlbXMgPSBmdW5jdGlvbiAoKSB7XG4gICAgbGV0IHRvU2VuZCA9IFtdO1xuICAgIGZvcihsZXQga2V5IGluICR3aW5kb3cuc2Vzc2lvblN0b3JhZ2Upe1xuICAgICAgbGV0IG9iaiA9IEpTT04ucGFyc2UoJHdpbmRvdy5zZXNzaW9uU3RvcmFnZVtrZXldKTtcbiAgICAgIHRvU2VuZC5wdXNoKHtcbiAgICAgICAgaWQ6IGtleSxcbiAgICAgICAgcXVhbnRpdHk6IG9ialsxXSxcbiAgICAgICAgcHJvZHVjdDoge1xuICAgICAgICAgIG5hbWU6IG9ialswXS5uYW1lLFxuICAgICAgICAgIHByaWNlOiBvYmpbMF0ucHJpY2UsXG4gICAgICAgICAgaW52ZW50b3J5OiBvYmpbMF0uaW52ZW50b3J5XG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgfVxuICAgIHJldHVybiB0b1NlbmQ7XG4gIH1cblxuICByZXR1cm4gQ2FydEZhY3Rvcnk7XG59KTtcblxuYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2NhcnQnLCB7XG4gICAgdXJsOiAnL2NhcnQnLFxuICAgIHRlbXBsYXRlVXJsOiAnanMvY2FydC9jYXJ0Lmh0bWwnLFxuICAgIGNvbnRyb2xsZXI6ICdDYXJ0Q3RybCcsXG4gICAgcmVzb2x2ZToge1xuICAgICAgY2FydEl0ZW1zOiBmdW5jdGlvbiAoQ2FydCwgQXV0aFNlcnZpY2UsICRyb290U2NvcGUpIHtcbiAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpXG4gICAgICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgICAgIGlmICghdXNlcikgcmV0dXJuIENhcnQuZmV0Y2hOb3RMb2dnZWRJbkl0ZW1zKCRyb290U2NvcGUuY2FydCk7XG4gICAgICAgICAgZWxzZSByZXR1cm4gQ2FydC5mZXRjaENhcnRJdGVtcygpO1xuICAgICAgICB9KVxuICAgICAgfVxuICAgIH1cbiAgfSlcbn0pXG5cbmFwcC5jb250cm9sbGVyKCdDYXJ0Q3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIGNhcnRJdGVtcywgQ2FydCwgQXV0aFNlcnZpY2UsICRyb290U2NvcGUsICR3aW5kb3cpIHtcblxuICAkc2NvcGUuY2FydEl0ZW1zID0gY2FydEl0ZW1zO1xuXG4gIGZ1bmN0aW9uIGdldFRvdGFsIChpdGVtcykge1xuICAgIHJldHVybiBfLnN1bShpdGVtcy5tYXAoaXRlbSA9PiBpdGVtLnByb2R1Y3QucHJpY2UgKiBpdGVtLnF1YW50aXR5KSk7XG4gIH1cblxuICAkc2NvcGUudG90YWwgPSBnZXRUb3RhbCgkc2NvcGUuY2FydEl0ZW1zKTtcblxuICAkc2NvcGUuZWRpdCA9IGZhbHNlO1xuXG4gICRzY29wZS5yZW1vdmVJdGVtID0gZnVuY3Rpb24gKGl0ZW0pIHtcbiAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKVxuICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgaWYgKCF1c2VyKSB7XG4gICAgICAgICR3aW5kb3cuc2Vzc2lvblN0b3JhZ2UucmVtb3ZlSXRlbShpdGVtLmlkKVxuICAgICAgICAkc2NvcGUuY2FydEl0ZW1zID0gQ2FydC5mZXRjaE5vdExvZ2dlZEluSXRlbXMoKTtcbiAgICAgICAgJHNjb3BlLnRvdGFsID0gZ2V0VG90YWwoJHNjb3BlLmNhcnRJdGVtcyk7XG4gICAgICB9XG4gICAgICBlbHNlIHJldHVybiBDYXJ0LnJlbW92ZUl0ZW0oaXRlbS5wcm9kdWN0LmlkKVxuICAgIH0pXG4gICAgLnRoZW4oKC4uLmFyZ3MpID0+IHtcbiAgICAgIGlmIChhcmdzWzBdKSB7XG4gICAgICAgIGxldCBpZHggPSAkc2NvcGUuY2FydEl0ZW1zLmluZGV4T2YoaXRlbSk7XG4gICAgICAgICRzY29wZS5jYXJ0SXRlbXMuc3BsaWNlKGlkeCwgMSk7XG4gICAgICAgICRzY29wZS50b3RhbCA9IGdldFRvdGFsKCRzY29wZS5jYXJ0SXRlbXMpO1xuICAgICAgfVxuICAgIH0pXG4gIH1cblxuICAkc2NvcGUuZWRpdFF1YW50aXR5ID0gZnVuY3Rpb24gKG5ld051bSwgaXRlbSkge1xuICAgICRzY29wZS5lZGl0ID0gZmFsc2U7XG4gICAgaWYobmV3TnVtID09PSAwKSB0aGlzLnJlbW92ZUl0ZW0oaXRlbSk7XG4gICAgZWxzZSBpZiAobmV3TnVtIDw9IGl0ZW0ucHJvZHVjdC5pbnZlbnRvcnkgJiYgbmV3TnVtID4gMCkge1xuICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKClcbiAgICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgICBpZiAoIXVzZXIpIHtcbiAgICAgICAgICBsZXQgdXNlclNlc3Npb24gPSAkd2luZG93LnNlc3Npb25TdG9yYWdlO1xuICAgICAgICAgIGxldCB0aGlzQXJyID0gSlNPTi5wYXJzZSh1c2VyU2Vzc2lvbi5nZXRJdGVtKGl0ZW0uaWQpKTsgLy9bcHJvZHVjdCwgcXVhbnRpdHldXG5cdFx0XHRcdFx0dGhpc0FyclsxXSA9IG5ld051bTtcblx0XHRcdFx0XHR1c2VyU2Vzc2lvbi5zZXRJdGVtKFtpdGVtLmlkXSwgSlNPTi5zdHJpbmdpZnkoW2l0ZW0ucHJvZHVjdCwgdGhpc0FyclsxXV0pKVxuICAgICAgICAgICRzY29wZS5jYXJ0SXRlbXMgPSBDYXJ0LmZldGNoTm90TG9nZ2VkSW5JdGVtcygpO1xuICAgICAgICAgICRzY29wZS50b3RhbCA9IGdldFRvdGFsKCRzY29wZS5jYXJ0SXRlbXMpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIHJldHVybiBDYXJ0LnVwZGF0ZVF1YW50aXR5KG5ld051bSwgaXRlbSlcbiAgICAgICAgfVxuICAgICAgfSlcbiAgICAgIC50aGVuKCguLi5hcmdzKSA9PiB7XG4gICAgICAgIGlmIChhcmdzWzBdKSB7XG4gICAgICAgICAgbGV0IGlkeCA9ICRzY29wZS5jYXJ0SXRlbXMuaW5kZXhPZihpdGVtKVxuICAgICAgICAgICRzY29wZS5jYXJ0SXRlbXNbaWR4XS5xdWFudGl0eSA9IGFyZ3NbMF0ucXVhbnRpdHk7XG4gICAgICAgICAgJHNjb3BlLnRvdGFsID0gZ2V0VG90YWwoJHNjb3BlLmNhcnRJdGVtcyk7XG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgfVxuXG4gIH1cblxuICAkc2NvcGUuZWRpdFZpZXcgPSBmdW5jdGlvbiAoKSB7XG4gICAgJHNjb3BlLmVkaXQgPSB0cnVlO1xuICB9XG5cbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ2luID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2xvZ2luJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvbG9nb3V0JykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgU2Vzc2lvbi5kZXN0cm95KCk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdTZXNzaW9uJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEFVVEhfRVZFTlRTKSB7XG5cbiAgICAgICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2VsZi5kZXN0cm95KCk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICB0aGlzLnVzZXIgPSBudWxsO1xuXG4gICAgICAgIHRoaXMuY3JlYXRlID0gZnVuY3Rpb24gKHNlc3Npb25JZCwgdXNlcikge1xuICAgICAgICAgICAgdGhpcy5pZCA9IHNlc3Npb25JZDtcbiAgICAgICAgICAgIHRoaXMudXNlciA9IHVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5kZXN0cm95ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgdGhpcy5pZCA9IG51bGw7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSBudWxsO1xuICAgICAgICB9O1xuXG4gICAgfSk7XG5cbn0pKCk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdob21lJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9ob21lL2hvbWUuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0xvZ2luJywgZnVuY3Rpb24gKCRodHRwLCAkcm9vdFNjb3BlLCAkcSkge1xuICAgIGxldCBsb2dpbkZhY3RvcnkgPSB7fTtcblxuICAgIGxvZ2luRmFjdG9yeS5wZXJzaXN0UHNldWRvQ2FydCA9IGZ1bmN0aW9uIChjYXJ0T2JqKSB7XG4gICAgICAgIGxldCBwcm9taXNlQXJyID0gW107XG4gICAgICAgIGZvciAobGV0IHByb2R1Y3RJZCBpbiBjYXJ0T2JqKSB7XG4gICAgICAgICAgICBwcm9taXNlQXJyLnB1c2goJGh0dHAucG9zdCgnL2FwaS9tZS9jYXJ0LycgKyBwcm9kdWN0SWQsIHtxdWFudGl0eTogY2FydE9ialtwcm9kdWN0SWRdWzFdfSkpO1xuICAgICAgICB9XG4gICAgICAgIGRlbGV0ZSAkcm9vdFNjb3BlLmNhcnQ7XG4gICAgICAgIHJldHVybiAkcS5hbGwocHJvbWlzZUFycik7XG4gICAgfVxuXG4gICAgcmV0dXJuIGxvZ2luRmFjdG9yeTtcbn0pO1xuXG5cbmFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbG9naW4nLCB7XG4gICAgICAgIHVybDogJy9sb2dpbicsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbG9naW4vbG9naW4uaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdMb2dpbkN0cmwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignTG9naW5DdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSwgJHJvb3RTY29wZSwgTG9naW4sIFJlc2V0UGFzc3dvcmQpIHtcblxuICAgICRzY29wZS5sb2dpbiA9IHt9O1xuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZExvZ2luID0gZnVuY3Rpb24gKGxvZ2luSW5mbykge1xuXG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAgICAgQXV0aFNlcnZpY2UubG9naW4obG9naW5JbmZvKVxuICAgICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgICAgICBpZiAoJHJvb3RTY29wZS5jYXJ0KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIExvZ2luLnBlcnNpc3RQc2V1ZG9DYXJ0KCRyb290U2NvcGUuY2FydClcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgncGFzc3dvcmRyZXNldCcsIHtcbiAgICAgICAgdXJsOiAnL3Jlc2V0LzpoYXNoSWQnICxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9wYXNzd29yZFJlc2V0L3Jlc2V0Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAncmVzZXRDdHJsJ1xuICAgIH0pXG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnZm9yZ290UGFzc3dvcmQnLCB7XG4gICAgICAgICAgdXJsOiAnL2ZvcmdvdHBhc3N3b3JkJyxcbiAgICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3Bhc3N3b3JkUmVzZXQvZm9yZ290UGFzc3dvcmQuaHRtbCcsXG4gICAgICAgICAgY29udHJvbGxlcjogJ2ZvcmdvdFBhc3N3b3JkQ3RybCdcbiAgICB9KTtcbn0pO1xuXG5cblxuYXBwLmZhY3RvcnkoJ1Jlc2V0UGFzc3dvcmQnLCBmdW5jdGlvbigkaHR0cCl7XG4gIHJldHVybiB7XG4gICAgY2hlY2tIYXNoUm91dGU6IGZ1bmN0aW9uKGhhc2gpe1xuICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9wYXNzd29yZC9yZXNldFBhc3N3b3JkLz91dz0nICsgaGFzaClcbiAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSlcbiAgICB9LFxuICAgIHJlc2V0VXNlclBhc3N3b3JkOiBmdW5jdGlvbihkYXRhKXtcbiAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvcGFzc3dvcmQvcmVzZXRQYXNzd29yZCcsIGRhdGEpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpXG4gICAgfSxcbiAgICBzZW5kRm9yZ290RW1haWw6IGZ1bmN0aW9uKGVtYWlsKXtcbiAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL21haWxlci9yZXNldFBhc3N3b3JkJywge2VtYWlsOiBlbWFpbH0pXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpXG4gICAgfVxuICB9XG59KVxuXG5hcHAuY29udHJvbGxlcigncmVzZXRDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCAkc3RhdGVQYXJhbXMsIFJlc2V0UGFzc3dvcmQsIFVzZXIpe1xuICBsZXQgaGFzaElkID0gJHN0YXRlUGFyYW1zLmhhc2hJZDtcbiAgbGV0IHBhc3N3b3JkID0gJHNjb3BlLnBhc3N3b3JkO1xuICAkc2NvcGUucGFzc3dvcmRSZXNldENvbXBsZXRlID0gZmFsc2U7XG4gICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgJHNjb3BlLnJlc2V0UGFzc3dvcmQgPSBmdW5jdGlvbihwYXNzd29yZCl7XG4gICAgUmVzZXRQYXNzd29yZC5jaGVja0hhc2hSb3V0ZShoYXNoSWQpXG4gICAgLnRoZW4oZW1haWwgPT4ge1xuICAgICAgaWYoZW1haWwpe1xuICAgICAgICBsZXQgcmVxQm9keSA9IHtlbWFpbDogZW1haWwsIHBhc3N3b3JkOiBwYXNzd29yZH07XG4gICAgICAgIHJldHVybiBSZXNldFBhc3N3b3JkLnJlc2V0VXNlclBhc3N3b3JkKHJlcUJvZHkpXG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdubyBlbWFpbCBmb3VuZCcpO1xuICAgICAgfVxuICAgIH0pXG4gICAgLnRoZW4odXBkYXRlZFVzZXIgPT4ge1xuICAgICAgJHNjb3BlLnBhc3N3b3JkUmVzZXRDb21wbGV0ZSA9IHRydWU7XG4gICAgfSlcbiAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgJHNjb3BlLmVycm9yID0gJ0ZvciB5b3VyIHNlY3VyaXR5LCB3ZVxcJ3ZlIHRpbWVkIG91dCB0aGUgcGFzc3dvcmQgcmVzZXQgcmVxdWVzdC4gIFBsZWFzZSBjbGljayBGb3Jnb3QgUGFzc3dvcmQgYWdhaW4gYW5kIGNvbWUgYmFjayA6KSdcblxuICAgIH0pXG4gIH1cbn0pXG5cbmFwcC5jb250cm9sbGVyKCdmb3Jnb3RQYXNzd29yZEN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIFJlc2V0UGFzc3dvcmQpe1xuICBsZXQgZW1haWxBZGRyZXNzID0gJHNjb3BlLmVtYWlsO1xuICAkc2NvcGUuZW1haWxTZW50ID0gZmFsc2U7XG4gICRzY29wZS5zZW5kRm9yZ290RW1haWwgPSBmdW5jdGlvbihlbWFpbEFkZHJlc3Mpe1xuICAgIFJlc2V0UGFzc3dvcmQuc2VuZEZvcmdvdEVtYWlsKGVtYWlsQWRkcmVzcylcbiAgICAudGhlbihkYXRhID0+IHtcbiAgICAgICRzY29wZS5lbWFpbFNlbnQgPSB0cnVlO1xuICAgIH0pXG4gIH1cbn0pXG4iLCJhcHAuY29udHJvbGxlcignUHJvZmlsZUN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIG1lKXtcbiAgJHNjb3BlLm1lID0gbWU7XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3Byb2ZpbGUnLCB7XG4gICAgdXJsOiAnL3Byb2ZpbGUnLFxuICAgIHRlbXBsYXRlVXJsOiAnanMvcHJvZmlsZS9wcm9maWxlLmh0bWwnLFxuICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQ3RybCcsXG4gICAgcmVzb2x2ZToge1xuICAgICAgbWU6IGZ1bmN0aW9uKFVzZXIsIEF1dGhTZXJ2aWNlKXtcbiAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpO1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3NpZ251cCcsIHtcbiAgICAgICAgdXJsOiAnL3NpZ251cCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvc2lnbnVwL3NpZ251cC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ3NpZ25VcEN0cmwnXG4gICAgfSk7XG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ3NpZ25VcEN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIFVzZXIsIEF1dGhTZXJ2aWNlLCAkc3RhdGUsICRyb290U2NvcGUsIExvZ2luLCAkd2luZG93LCBNYWlsZXIpe1xuICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICRzY29wZS5zZW5kU2lnbnVwID0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAvL0Vycm9yIGhhbmRsaW5nIGluIGNvbnRyb2xsZXIgdG8ga2VlcCBIVE1MXG4gICAgLy9lYXN5IHRvIGRlYWwgd2l0aCBpbnN0ZWFkIG9mIGhhdmluZyBhIGJ1bmNoXG4gICAgLy9vZiBoaWRkZW4gZGl2cyBhbmQgc3BhbnNcbiAgICBpZigkc2NvcGUuc2lnbnVwRm9ybS4kZXJyb3IuZW1haWwpICRzY29wZS5lcnJvciA9ICdQbGVhc2UgZW50ZXIgYSB2YWxpZCBlbWFpbCc7XG4gICAgZWxzZSBpZigkc2NvcGUuc2lnbnVwRm9ybS4kZXJyb3IubWlubGVuZ3RoKSAkc2NvcGUuZXJyb3IgPSAnUGFzc3dvcmQgbXVzdCBiZSBhdCBsZWFzdCA4IGNoYXJhY3RlcnMnO1xuICAgIGVsc2UgaWYoJHNjb3BlLnNpZ251cEZvcm0uJGVycm9yLm1heGxlbmd0aCkgJHNjb3BlLmVycm9yID0gJ1Bhc3N3b3JkIG11c3QgYmUgbGVzcyB0aGFuIDMyIGNoYXJhY3RlcnMnO1xuICAgIGVsc2UgaWYoJHNjb3BlLnNpZ251cEZvcm0uJGVycm9yLnJlcXVpcmVkKSAkc2NvcGUuZXJyb3IgPSAnQWxsIGZpZWxkcyBhcmUgcmVxdWlyZWQnO1xuICAgIGVsc2Uge1xuICAgICAgVXNlci5zaWdudXAoc2lnbnVwSW5mbylcbiAgICAgIC50aGVuKGZ1bmN0aW9uICgpe1xuICAgICAgICAvL2xvZyB1c2VyIGluIGlmIHRoZSBzaWdudXAgd2FzIHN1Y2Nlc3NmdWxcbiAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmxvZ2luKHtlbWFpbDogc2lnbnVwSW5mby5lbWFpbCwgcGFzc3dvcmQ6IHNpZ251cEluZm8ucGFzc3dvcmR9KVxuICAgICAgfSlcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgbGV0IGNhcnQgPSB7fTtcbiAgICAgICAgZm9yKGxldCBrZXkgaW4gJHdpbmRvdy5zZXNzaW9uU3RvcmFnZSl7XG4gICAgICAgICAgbGV0IG9iaiA9IEpTT04ucGFyc2UoJHdpbmRvdy5zZXNzaW9uU3RvcmFnZVtrZXldKTtcbiAgICAgICAgICBjYXJ0W2tleV0gPSBvYmo7XG4gICAgICAgIH1cbiAgICAgICAgICBpZiAoY2FydCkge1xuICAgICAgICAgICAgICByZXR1cm4gTG9naW4ucGVyc2lzdFBzZXVkb0NhcnQoY2FydClcbiAgICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnRoZW4oKCkgPT4gIE1haWxlci5zZW5kV2VsY29tZU1lc3NhZ2Uoc2lnbnVwSW5mbykpXG4gICAgICAudGhlbigoKSA9PiAkc3RhdGUuZ28oJ2hvbWUnKSlcbiAgICAgIC5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICRzY29wZS5lcnJvciA9ICdUaGVyZSB3YXMgYW4gZXJyb3IuIEVycm9yIDQzMjA1Mi4gUGxlYXNlIGNvbnRhY3QgUGF5dG9uJztcbiAgICAgIH0pO1xuICAgIH07XG4gIH07XG5cbn0pXG4iLCJhcHAuY29udHJvbGxlcignYWRtaW5PcmRlcnNDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBvcmRlcnMpe1xuICAkc2NvcGUub3JkZXJzID0gb3JkZXJzXG59KVxuXG5hcHAuY29udHJvbGxlcignYWRtaW5PcmRlckRldGFpbEN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIE9yZGVyLCAkc3RhdGVQYXJhbXMsIEFkZHJlc3MsICRzdGF0ZSwgJHEpe1xuICBsZXQgb3JkZXJJZCA9ICRzdGF0ZVBhcmFtcy5vcmRlcklkO1xuICAkc2NvcGUub3JkZXIgPSB7fTtcbiAgT3JkZXIuZ2V0T25lT3JkZXJTdW1tYXJ5KG9yZGVySWQpXG4gIC50aGVuKG9yZGVyU3VtbWFyeSA9PiB7XG4gICAgJHNjb3BlLm9yZGVyLm9yZGVyU3VtbWFyeSA9IG9yZGVyU3VtbWFyeVxuICAgIHJldHVybiBBZGRyZXNzLmdldE9uZUFkZHJlc3Mob3JkZXJTdW1tYXJ5LnNoaXBwaW5nSWQpXG4gIH0pXG4gIC50aGVuKGFkZHJlc3MgPT4ge1xuICAgICRzY29wZS5vcmRlci5vcmRlckFkZHJlc3MgPSBhZGRyZXNzO1xuICAgIHJldHVybiBPcmRlci5nZXRBbGxPcmRlckRldGFpbHMob3JkZXJJZClcbiAgfSlcbiAgLnRoZW4ob3JkZXJEZXRhaWxzID0+ICRzY29wZS5vcmRlci5vcmRlckRldGFpbHMgPSBvcmRlckRldGFpbHMpXG4gIC5jYXRjaChlcnJvciA9PiBjb25zb2xlLmVycm9yKGVycm9yKSlcblxuICAkc2NvcGUuc2F2ZUNoYW5nZXMgPSBmdW5jdGlvbihvcmRlcil7XG4gICAgbGV0IG9yZGVyU3VtbWFyeSA9IG9yZGVyLm9yZGVyU3VtbWFyeTsgLy9USElTIEFOIE9CSlxuICAgIGxldCBvcmRlckRldGFpbHMgPSBvcmRlci5vcmRlckRldGFpbHM7IC8vVEhJUyBJUyBBTiBBUlJBWVxuXG4gICAgT3JkZXIudXBkYXRlT25lT3JkZXJTdW1tYXJ5KG9yZGVyU3VtbWFyeS5pZCwgb3JkZXJTdW1tYXJ5KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiBQcm9taXNlLmFsbChvcmRlckRldGFpbHMubWFwKG9yZGVyRGV0YWlsID0+IE9yZGVyLnVwZGF0ZU9yZGVyRGV0YWlscyhvcmRlckRldGFpbC5pZCwgb3JkZXJEZXRhaWwpKSlcbiAgICB9KVxuICAgIC50aGVuKGRldGFpbHMgPT4ge1xuICAgICAgLy9Ob3cgd2UgY2hlY2sgaWYgYWxsIGRldGFpbHMgYXJlIHByb2Nlc3NlZCB0byBjaGFuZ2UgdGhlIG1hc3RlciBzdW1tYXJ5ICdwcm9jZXNzZWQnXG4gICAgICBsZXQgcHJvY2Vzc2VkO1xuICAgICAgZGV0YWlscy5maWx0ZXIoZGV0YWlsID0+ICFkZXRhaWwucHJvY2Vzc2VkKS5sZW5ndGggPiAwID8gcHJvY2Vzc2VkID0gZmFsc2UgOiBwcm9jZXNzZWQgPSB0cnVlO1xuICAgICAgcmV0dXJuIE9yZGVyLnVwZGF0ZU9uZU9yZGVyU3VtbWFyeShvcmRlclN1bW1hcnkuaWQsIHtwcm9jZXNzZWQ6IHByb2Nlc3NlZH0pXG4gICAgfSlcbiAgICAudGhlbigoKSA9PiAkc3RhdGUuZ28oJ2FkbWluLm9yZGVycycpKVxuICAgIC5jYXRjaChlcnJvciA9PiBjb25zb2xlLmVycm9yKGVycm9yKSlcbiAgfVxufSlcbiIsImFwcC5jb250cm9sbGVyKCdhZG1pbkN0cmwnLCBmdW5jdGlvbigpe1xuICAvL0VNUFRZIEZPUiBOT1dcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhZG1pbicsIHtcbiAgICAgICAgdXJsOiAnL2FkbWluJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hZG1pbi9ob21lL2FkbWluLmh0bWwnLFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgYXV0aEFkbWluOiBmdW5jdGlvbihBdXRoU2VydmljZSwgJHJvb3RTY29wZSwgJHN0YXRlKXtcbiAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKVxuICAgICAgICAgICAgLnRoZW4odXNlciA9PiB7XG4gICAgICAgICAgICAgIGlmKCF1c2VyLmlzQWRtaW4pICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICAgICAgICBlbHNlICRyb290U2NvcGUuaXNBZG1pbiA9IHRydWU7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY29udHJvbGxlcjogJ2FkbWluQ3RybCdcbiAgICB9KVxuICAgIC5zdGF0ZSgnYWRtaW4udXNlcnMnLCB7XG4gICAgICB1cmw6ICcvdXNlcnMnLFxuICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hZG1pbi91c2Vycy91c2Vycy5hZG1pbi5odG1sJyxcbiAgICAgIGNvbnRyb2xsZXI6ICd1c2Vyc0FkbWluQ3RybCdcbiAgICB9KVxuICAgIC5zdGF0ZSgnYWRtaW4udXNlckRldGFpbCcsIHtcbiAgICAgIHVybDogJy91c2Vycy86dXNlcklkJyxcbiAgICAgIHRlbXBsYXRlVXJsOiAnanMvYWRtaW4vdXNlcnMvdXNlci5kZXRhaWwuYWRtaW4uaHRtbCcsXG4gICAgICBjb250cm9sbGVyOiAndXNlcnNEZXRhaWxBZG1pbkN0cmwnXG4gICAgfSlcbiAgICAuc3RhdGUoJ2FkbWluLnByb2R1Y3RzJywge1xuICAgICAgICB1cmw6ICcvcHJvZHVjdHMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2FkbWluL3Byb2R1Y3RzL3Byb2R1Y3RzLmFkbWluLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnYWRtaW5Qcm9kdWN0c0N0cmwnXG4gICAgfSlcbiAgICAuc3RhdGUoJ2FkbWluLnByb2R1Y3REZXRhaWwnLCB7XG4gICAgICB1cmw6ICcvcHJvZHVjdHMvOnByb2R1Y3RJZCcsXG4gICAgICB0ZW1wbGF0ZVVybDogJ2pzL2FkbWluL3Byb2R1Y3RzL3Byb2R1Y3QuZGV0YWlsLmFkbWluLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2FkbWluUHJvZHVjdERldGFpbEN0cmwnXG4gICAgfSlcbiAgICAuc3RhdGUoJ2FkbWluLm9yZGVycycsIHtcbiAgICAgIHVybDogJy9vcmRlcnMnLFxuICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hZG1pbi9vcmRlcnMvb3JkZXJzLmFkbWluLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2FkbWluT3JkZXJzQ3RybCcsXG4gICAgICByZXNvbHZlOiB7XG4gICAgICAgIG9yZGVyczogZnVuY3Rpb24oT3JkZXIpe1xuICAgICAgICAgIHJldHVybiBPcmRlci5nZXRBbGxPcmRlclN1bW1hcmllcygpXG4gICAgICAgICAgLnRoZW4ob3JkZXJzID0+IHtcbiAgICAgICAgICAgIHJldHVybiBvcmRlcnNcbiAgICAgICAgICB9KVxuICAgICAgICAgIC5jYXRjaChlcnJvciA9PiBjb25zb2xlLmVycm9yKGVycm9yKSlcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pXG4gICAgLnN0YXRlKCdhZG1pbi5vcmRlckRldGFpbCcsIHtcbiAgICAgIHVybDogJy9vcmRlcnMvOm9yZGVySWQnLFxuICAgICAgdGVtcGxhdGVVcmw6ICdqcy9hZG1pbi9vcmRlcnMvb3JkZXIuZGV0YWlsLmFkbWluLmh0bWwnLFxuICAgICAgY29udHJvbGxlcjogJ2FkbWluT3JkZXJEZXRhaWxDdHJsJ1xuICAgIH0pXG5cbn0pXG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5jb250cm9sbGVyKCdhZG1pblByb2R1Y3RzQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgUHJvZHVjdCwgJHJvb3RTY29wZSl7XG5cbiAgJHJvb3RTY29wZS4kb24oJ3NlYXJjaGluZycsIGZ1bmN0aW9uKGUsIGRhdGEpe1xuICAgICRzY29wZS5zZWFyY2ggPSBkYXRhO1xuICB9KVxuXG4gIFByb2R1Y3QuZ2V0QWxsKClcbiAgLnRoZW4ocHJvZHVjdHMgPT4ge1xuICAgICRzY29wZS5wcm9kdWN0cyA9IHByb2R1Y3RzXG4gIH0pXG4gIC5jYXRjaChlcnJvciA9PiB7XG4gICAgY29uc29sZS5sb2coZXJyb3IpXG4gIH0pXG59KVxuXG5cbmFwcC5jb250cm9sbGVyKCdhZG1pblByb2R1Y3REZXRhaWxDdHJsJywgZnVuY3Rpb24oJHNjb3BlLCAkc3RhdGUsIFByb2R1Y3QsICRzdGF0ZVBhcmFtcyl7XG4gIGxldCBwcm9kdWN0SWQgPSAkc3RhdGVQYXJhbXMucHJvZHVjdElkO1xuXG4gIFByb2R1Y3QuZ2V0T25lKHByb2R1Y3RJZClcbiAgLnRoZW4ocHJvZHVjdCA9PiAkc2NvcGUucHJvZHVjdCA9IHByb2R1Y3QpXG4gIC5jYXRjaChlcnJvciA9PiBjb25zb2xlLmVycm9yKGVycm9yKSlcblxuICAkc2NvcGUuc2F2ZUNoYW5nZXMgPSBmdW5jdGlvbihmb3JtRGF0YSl7XG4gICAgUHJvZHVjdC5lZGl0T25lKHByb2R1Y3RJZCwgZm9ybURhdGEpXG4gICAgLnRoZW4odXBkYXRlZFByb2R1Y3QgPT4gJHN0YXRlLmdvKCdhZG1pbi5wcm9kdWN0cycpKVxuICB9XG59KVxuIiwiYXBwLmNvbnRyb2xsZXIoJ3VzZXJzQWRtaW5DdHJsJywgZnVuY3Rpb24oJHNjb3BlLCBVc2VyLCAkcm9vdFNjb3BlKXtcblxuICAkcm9vdFNjb3BlLiRvbignc2VhcmNoaW5nJywgZnVuY3Rpb24oZSwgZGF0YSl7XG4gICAgJHNjb3BlLnNlYXJjaCA9IGRhdGE7XG4gIH0pXG4gIC8vR2V0IGFsbCBhbmQgYWRkIHRvIHNjb3BlXG4gIFVzZXIuZ2V0QWxsKClcbiAgLnRoZW4odXNlcnMgPT4gJHNjb3BlLnVzZXJzID0gdXNlcnMpXG4gIC5jYXRjaChlcnJvciA9PiBjb25zb2xlLmVycm9yKGVycm9yKSk7XG59KVxuXG5hcHAuY29udHJvbGxlcigndXNlcnNEZXRhaWxBZG1pbkN0cmwnLCBmdW5jdGlvbigkc2NvcGUsIFVzZXIsICRzdGF0ZVBhcmFtcywgJHN0YXRlKXtcbiAgbGV0IHVzZXJJZCA9IHBhcnNlSW50KCRzdGF0ZVBhcmFtcy51c2VySWQpO1xuXG4gIC8vR2V0IGFsbCBhbmQgYWRkIHRvIHNjb3BlXG4gIFVzZXIuZ2V0T25lKHVzZXJJZClcbiAgLnRoZW4odXNlciA9PiB7XG4gICAgJHNjb3BlLnVzZXIgPSB1c2VyO1xuICB9KVxuICAuY2F0Y2goZXJyb3IgPT4gY29uc29sZS5lcnJvcihlcnJvcikpO1xuXG4gICRzY29wZS5zYXZlQ2hhbmdlcyA9IGZ1bmN0aW9uKGZvcm1EYXRhKXtcbiAgICBVc2VyLmVkaXRPbmUodXNlcklkLCBmb3JtRGF0YSlcbiAgICAudGhlbigoKSA9PiAkc3RhdGUuZ28oJ2FkbWluLnVzZXJzJykpXG4gICAgLmNhdGNoKGVycm9yID0+IGNvbnNvbGUuZXJyb3IoZXJyb3IpKVxuICB9XG5cbn0pXG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5mYWN0b3J5KCdBZGRyZXNzJywgZnVuY3Rpb24oJGh0dHApIHtcbiAgICByZXR1cm4ge1xuICAgICAgICBnZXRNeUFkZHJlc3NlczogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21lL2FkZHJlc3NlcycpXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICAgICAgfSxcbiAgICAgICAgY3JlYXRlTmV3QWRkcmVzczogZnVuY3Rpb24oaW5mb3JtYXRpb24sIHVzZXIpIHtcbiAgICAgICAgICAgIGlmICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvbWUvYWRkcmVzc2VzJywgaW5mb3JtYXRpb24pXG4gICAgICAgICAgICAgICAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2FkZHJlc3MnLCBpbmZvcm1hdGlvbilcbiAgICAgICAgICAgICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpXG4gICAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGdldE9uZUFkZHJlc3M6IGZ1bmN0aW9uKGlkKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2FkZHJlc3MvJyArIGlkKVxuICAgICAgICAgICAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSlcbiAgICAgICAgfSxcbiAgICAgICAgcmVtb3ZlQWRkcmVzc0Zyb21Vc2VyOiBmdW5jdGlvbihhZGRyZXNzSWQsIHVzZXJJZCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9hZGRyZXNzLycgKyBhZGRyZXNzSWQgKyAnLycgKyB1c2VySWQpXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKVxuICAgICAgICB9XG4gICAgfVxufSk7XG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5mYWN0b3J5KCdDYXJkJywgZnVuY3Rpb24gKCRodHRwKSB7XG4gIHJldHVybiB7XG4gICAgZ2V0TXlDYXJkczogZnVuY3Rpb24oKXtcbiAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvbWUvY2FyZHMnKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICB9LFxuICAgIGNyZWF0ZU5ld0NhcmRGb3JVc2VyOiBmdW5jdGlvbihjYXJkKXtcbiAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL21lL2NhcmRzJywgY2FyZClcbiAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gICAgfSxcbiAgICBjcmVhdGVOZXdDYXJkTm9Vc2VyOiBmdW5jdGlvbihjYXJkKXtcbiAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2NhcmQnLCBjYXJkKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICB9LFxuICAgIHJlbW92ZUNhcmRGcm9tVXNlcjogZnVuY3Rpb24oY2FyZElkLCB1c2VySWQpe1xuICAgICAgcmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS9jYXJkLycgKyBjYXJkSWQgKyAnLycgKyB1c2VySWQpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpXG4gICAgfVxuICB9XG59KTtcbiIsImFwcC5mYWN0b3J5KCdGdWxsc3RhY2tQaWNzJywgZnVuY3Rpb24gKCkge1xuICAgIHJldHVybiBbXG4gICAgICAgICdodHRwczovL3Bicy50d2ltZy5jb20vbWVkaWEvQjdnQlh1bENBQUFYUWNFLmpwZzpsYXJnZScsXG4gICAgICAgICdodHRwczovL2ZiY2RuLXNwaG90b3MtYy1hLmFrYW1haWhkLm5ldC9ocGhvdG9zLWFrLXhhcDEvdDMxLjAtOC8xMDg2MjQ1MV8xMDIwNTYyMjk5MDM1OTI0MV84MDI3MTY4ODQzMzEyODQxMTM3X28uanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLUxLVXNoSWdBRXk5U0suanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNzktWDdvQ01BQWt3N3kuanBnJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLVVqOUNPSUlBSUZBaDAuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNnlJeUZpQ0VBQXFsMTIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRS1UNzVsV0FBQW1xcUouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRXZaQWctVkFBQWs5MzIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRWdOTWVPWElBSWZEaEsuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DRVF5SUROV2dBQXU2MEIuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQ0YzVDVRVzhBRTJsR0ouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQWVWdzVTV29BQUFMc2ouanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQWFKSVA3VWtBQWxJR3MuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DQVFPdzlsV0VBQVk5RmwuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CLU9RYlZyQ01BQU53SU0uanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9COWJfZXJ3Q1lBQXdSY0oucG5nOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNVBUZHZuQ2NBRUFsNHguanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CNHF3QzBpQ1lBQWxQR2guanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9CMmIzM3ZSSVVBQTlvMUQuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9Cd3BJd3IxSVVBQXZPMl8uanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9Cc1NzZUFOQ1lBRU9oTHcuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSjR2TGZ1VXdBQWRhNEwuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSTd3empFVkVBQU9QcFMuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSWRIdlQyVXNBQW5uSFYuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DR0NpUF9ZV1lBQW83NVYuanBnOmxhcmdlJyxcbiAgICAgICAgJ2h0dHBzOi8vcGJzLnR3aW1nLmNvbS9tZWRpYS9DSVM0SlBJV0lBSTM3cXUuanBnOmxhcmdlJ1xuICAgIF07XG59KTtcbiIsImFwcC5mYWN0b3J5KCdNYWlsZXInLCBmdW5jdGlvbigkaHR0cCl7XG4gIHJldHVybiB7XG4gICAgc2VuZFdlbGNvbWVNZXNzYWdlOiBmdW5jdGlvbihkYXRhKXtcbiAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL21haWxlci93ZWxjb21lTWVzc2FnZScsIGRhdGEpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpXG4gICAgfVxuICB9XG59KVxuIiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZmFjdG9yeSgnT3JkZXInLCBmdW5jdGlvbiAoJGh0dHApIHtcbiAgcmV0dXJuIHtcbiAgICBnZXRBbGxPcmRlclN1bW1hcmllczogZnVuY3Rpb24oKXtcbiAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvb3JkZXJzJylcbiAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gICAgfSxcbiAgICBnZXRNeU9yZGVyU3VtbWFyaWVzOiBmdW5jdGlvbigpe1xuICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9tZS9vcmRlcnMnKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICB9LFxuICAgIGdldE15T3JkZXJEZXRhaWxzOiBmdW5jdGlvbihvcmRlclN1bW1hcnlJZCl7XG4gICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL21lL29yZGVycy8nICsgb3JkZXJTdW1tYXJ5SWQpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuICAgIH0sXG4gICAgZ2V0T25lT3JkZXJTdW1tYXJ5OiBmdW5jdGlvbihvcmRlclN1bW1hcnlJZCl7XG4gICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL29yZGVycy8nICsgb3JkZXJTdW1tYXJ5SWQpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuICAgIH0sXG4gICAgdXBkYXRlT25lT3JkZXJTdW1tYXJ5OiBmdW5jdGlvbihvcmRlclN1bW1hcnlJZCwgZGF0YSl7XG4gICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL29yZGVycy8nICsgb3JkZXJTdW1tYXJ5SWQsIGRhdGEpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuICAgIH0sXG4gICAgdXBkYXRlT3JkZXJEZXRhaWxzOiBmdW5jdGlvbihvcmRlckRldGFpbHNJZCwgZGF0YSl7XG4gICAgICByZXR1cm4gJGh0dHAucHV0KCcvYXBpL29yZGVycy9kZXRhaWxzLycgKyBvcmRlckRldGFpbHNJZCwgZGF0YSlcbiAgICAgIC50aGVuKCByZXMgPT4gcmVzLmRhdGEpXG4gICAgfSxcbiAgICBnZXRBbGxPcmRlckRldGFpbHM6IGZ1bmN0aW9uKG9yZGVyU3VtbWFyeUlkKXtcbiAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvb3JkZXJzLycgKyBvcmRlclN1bW1hcnlJZCArICcvZGV0YWlscycpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuICAgIH0sXG5cbiAgICBzZW5kVG9TdHJpcGU6IGZ1bmN0aW9uKGNoYXJnZURldGFpbHMpe1xuICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvY2FyZC9zdHJpcGUnLCBjaGFyZ2VEZXRhaWxzKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICB9LFxuXG4gICAgY3JlYXRlT3JkZXJTdW1tYXJ5OiBmdW5jdGlvbihvcmRlckRhdGEpIHtcbiAgICAgIG9yZGVyRGF0YS5wcmljZVRvdGFsICo9IDEwMDtcbiAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL29yZGVycycsIG9yZGVyRGF0YSlcbiAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gICAgfSxcblxuICAgIGNyZWF0ZU9yZGVyRGV0YWlsczogZnVuY3Rpb24ob3JkZXJEZXRhaWxzKXtcbiAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL29yZGVycy9kZXRhaWxzJywgb3JkZXJEZXRhaWxzKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICB9XG4gIH1cbn0pXG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5mYWN0b3J5KCdQcm9kdWN0JywgZnVuY3Rpb24gKCRodHRwKSB7XG5cblx0dmFyIFByb2R1Y3RGYWN0b3J5ID0ge307XG5cblx0UHJvZHVjdEZhY3RvcnkudXJsID0gJy9hcGkvcHJvZHVjdHMnXG5cblx0UHJvZHVjdEZhY3RvcnkuZ2V0QWxsID0gZnVuY3Rpb24ocXVlcnkpIHtcblx0XHRpZighcXVlcnkpIHF1ZXJ5ID0gJyc7XG5cdFx0cmV0dXJuICRodHRwLmdldChQcm9kdWN0RmFjdG9yeS51cmwgKyBxdWVyeSlcblx0XHQudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuXHR9XG5cblx0UHJvZHVjdEZhY3RvcnkuZ2V0T25lID0gZnVuY3Rpb24oaWQpIHtcblx0XHRyZXR1cm4gJGh0dHAuZ2V0KFByb2R1Y3RGYWN0b3J5LnVybCArICcvJyArIGlkKVxuXHRcdC50aGVuKHJlcyA9PiByZXMuZGF0YSlcblx0fVxuXG5cdFByb2R1Y3RGYWN0b3J5LmVkaXRPbmUgPSBmdW5jdGlvbihpZCwgZGF0YSl7XG5cdFx0cmV0dXJuICRodHRwLnB1dChQcm9kdWN0RmFjdG9yeS51cmwgKyAnLycgKyBpZCwgZGF0YSlcblx0XHQudGhlbihyZXMgPT4gcmVzLmRhdGEpXG5cdH1cblxuXHRyZXR1cm4gUHJvZHVjdEZhY3Rvcnk7XG59KVxuIiwiYXBwLmZhY3RvcnkoJ1Jldmlld0ZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcbiAgcmV0dXJuIHtcbiAgICBhZGRSZXZpZXc6IGZ1bmN0aW9uIChyZXZpZXcsIHByb2R1Y3RJZCkge1xuICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvcmV2aWV3cy8nICsgcHJvZHVjdElkLCB7c3RhcnM6IHJldmlldy5zdGFycywgZGVzY3JpcHRpb246IHJldmlldy5kZXNjcmlwdGlvbn0pXG4gICAgfSxcbiAgICBnZXRSZXZpZXdzOiBmdW5jdGlvbiAocHJvZHVjdElkKSB7XG4gICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL3Jldmlld3MvJyArIHByb2R1Y3RJZClcbiAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gICAgfVxuICB9XG59KTtcbiIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmZhY3RvcnkoJ1VzZXInLCBmdW5jdGlvbiAoJGh0dHApIHtcbiAgcmV0dXJuIHtcbiAgICBzaWdudXA6IGZ1bmN0aW9uKHNpZ251cERhdGEpe1xuICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvdXNlcnMnLCBzaWdudXBEYXRhKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKTtcbiAgICB9LFxuXG4gICAgZ2V0QWxsOiBmdW5jdGlvbigpe1xuICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS91c2VycycpXG4gICAgICAudGhlbihyZXMgPT4gcmVzLmRhdGEpO1xuICAgIH0sXG5cbiAgICBnZXRPbmU6IGZ1bmN0aW9uKGlkKXtcbiAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvdXNlcnMvJytpZClcbiAgICAgIC50aGVuKHJlcyA9PiByZXMuZGF0YSk7XG4gICAgfSxcblxuICAgIGVkaXRPbmU6IGZ1bmN0aW9uKGlkLCBkYXRhKXtcbiAgICAgIHJldHVybiAkaHR0cC5wdXQoJy9hcGkvdXNlcnMvJyArIGlkLCBkYXRhKVxuICAgICAgLnRoZW4ocmVzID0+IHJlcy5kYXRhKVxuICAgIH1cbiAgfVxufSlcbiIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmZhY3RvcnkoJ1V0aWxpdHknLCBmdW5jdGlvbiAoJGh0dHApIHtcbiAgcmV0dXJuIHtcbiAgICBjb252ZXJ0Q2VudHNUb0RvbGxhcnM6IGZ1bmN0aW9uKGNlbnRzKXtcbiAgICAgIHJldHVybiBjZW50cyAvIDEwMDtcbiAgICB9LFxuXG4gICAgY29udmVydERvbGxhcnNUb0NlbnRzOiBmdW5jdGlvbihkb2xsYXJzKXtcbiAgICAgIHJldHVybiBkb2xsYXJzICogMTAwO1xuICAgIH0sXG5cbiAgICBjb252ZXJ0VG9RdWVyeTogZnVuY3Rpb24oanNvbil7XG4gICAgICB2YXIgc3VwZXJRdWVyeSA9IFtdO1xuICAgICAgZm9yICh2YXIga2V5IGluIGpzb24pIHtcbiAgICAgICAgaWYoanNvbi5oYXNPd25Qcm9wZXJ0eShrZXkpKXtcbiAgICAgICAgICBzdXBlclF1ZXJ5LnB1c2goanNvbltrZXldKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgc3VwZXJRdWVyeSA9ICc/JyArIHN1cGVyUXVlcnkuam9pbignJicpO1xuXG4gICAgICByZXR1cm4gc3VwZXJRdWVyeTtcbiAgICB9XG4gIH1cbn0pXG5cbiIsImFwcC5jb250cm9sbGVyKCdQcm9kdWN0RGV0YWlsQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIHByb2R1Y3QsIHByb2R1Y3RSZXZpZXdzLCBSZXZpZXdGYWN0b3J5KSB7XG4gICRzY29wZS52aWV3UmV2aWV3cyA9IGZhbHNlO1xuICAkc2NvcGUuYWRkUmV2aWV3ID0gZmFsc2U7XG4gICRzY29wZS5wcm9kdWN0ID0gcHJvZHVjdDtcbiAgJHNjb3BlLnByb2R1Y3RSZXZpZXdzID0gcHJvZHVjdFJldmlld3M7XG5cbn0pO1xuXG5hcHAuZGlyZWN0aXZlKCdhZGRSZXZpZXcnLCBmdW5jdGlvbiAoJHN0YXRlLCBSZXZpZXdGYWN0b3J5KSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9wcm9kdWN0L2RldGFpbC9hZGRSZXZpZXcuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSwgZWxlbSwgYXR0cnMpIHtcbiAgICAgICAgICBzY29wZS5zdGFycyA9IFsxLCAyLCAzLCA0LCA1XTtcbiAgICAgICAgICBzY29wZS5zdWJtaXRSZXZpZXcgPSBmdW5jdGlvbiAocmV2aWV3LCBwcm9kdWN0SWQpIHtcbiAgICAgICAgICAgIFJldmlld0ZhY3RvcnkuYWRkUmV2aWV3KHJldmlldywgcHJvZHVjdElkKTtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnY2FydCcpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn0pO1xuXG5hcHAuZGlyZWN0aXZlKCd2aWV3UmV2aWV3cycsIGZ1bmN0aW9uICgkc3RhdGUsIFJldmlld0ZhY3RvcnkpIHtcbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3Byb2R1Y3QvZGV0YWlsL3ZpZXdSZXZpZXdzLmh0bWwnLFxuICAgIH1cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3Byb2R1Y3QnLCB7XG4gICAgdXJsOiAnL3Byb2R1Y3RzLzppZCcsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9wcm9kdWN0L2RldGFpbC9wcm9kdWN0LmRldGFpbC5odG1sJyxcbiAgICBjb250cm9sbGVyOiAnUHJvZHVjdERldGFpbEN0cmwnLFxuICAgIHJlc29sdmU6IHtcbiAgICAgIHByb2R1Y3Q6IGZ1bmN0aW9uIChQcm9kdWN0LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgcmV0dXJuIFByb2R1Y3QuZ2V0T25lKCRzdGF0ZVBhcmFtcy5pZCk7XG4gICAgICB9LFxuICAgICAgcHJvZHVjdFJldmlld3M6IGZ1bmN0aW9uIChSZXZpZXdGYWN0b3J5LCAkc3RhdGVQYXJhbXMpIHtcbiAgICAgICAgcmV0dXJuIFJldmlld0ZhY3RvcnkuZ2V0UmV2aWV3cygkc3RhdGVQYXJhbXMuaWQpO1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5mYWN0b3J5KCdQcm9kdWN0TGlzdEZhY3RvcnknLCBmdW5jdGlvbigkd2luZG93LCAkaHR0cCwgQXV0aFNlcnZpY2UsICRyb290U2NvcGUsICRxKXtcblxuXHR2YXIgUHJvZHVjdExpc3RGYWN0b3J5ID0ge307XG5cblx0UHJvZHVjdExpc3RGYWN0b3J5LmFkZFByb2R1Y3QgPSBmdW5jdGlvbihwcm9kdWN0LCBxdWFudGl0eSkge1xuICAgIGNvbnNvbGUubG9nKCctLS0tLS0tLS0tSGVyZS0tLS0tLS0tJywgcHJvZHVjdCk7XG4gICAgJHJvb3RTY29wZS5jYXJ0ID0gJHJvb3RTY29wZS5jYXJ0IHx8IHt9O1xuICAgIHJldHVybiBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKVxuICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgaWYgKCF1c2VyKSB7XG5cdFx0XHRcdGxldCB1c2VyU2Vzc2lvbiA9ICR3aW5kb3cuc2Vzc2lvblN0b3JhZ2U7XG5cdFx0XHRcdGlmKHVzZXJTZXNzaW9uLmdldEl0ZW0ocHJvZHVjdC5pZCkpIHtcblx0XHRcdFx0XHRsZXQgdGhpc0FyciA9IEpTT04ucGFyc2UodXNlclNlc3Npb24uZ2V0SXRlbShwcm9kdWN0LmlkKSk7IC8vW3Byb2R1Y3QsIHF1YW50aXR5XVxuXHRcdFx0XHRcdHRoaXNBcnJbMV0gKz0gcXVhbnRpdHk7XG5cdFx0XHRcdFx0dXNlclNlc3Npb24uc2V0SXRlbShbcHJvZHVjdC5pZF0sIEpTT04uc3RyaW5naWZ5KFtwcm9kdWN0LCB0aGlzQXJyWzFdXSkpXG5cdFx0XHRcdH0gZWxzZXtcblx0XHRcdFx0XHR1c2VyU2Vzc2lvbi5zZXRJdGVtKFtwcm9kdWN0LmlkXSwgSlNPTi5zdHJpbmdpZnkoW3Byb2R1Y3QsIHF1YW50aXR5XSkpXG5cdFx0XHRcdH1cbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9tZS9jYXJ0LycgKyBwcm9kdWN0LmlkLCB7cXVhbnRpdHk6IHF1YW50aXR5fSlcbiAgICAgIH1cbiAgICB9KVxuXHRcdC50aGVuKCguLi5hcmdzKSA9PiB7XG4gICAgICBpZiAoYXJnc1swXSkgcmV0dXJuIGFyZ3NbMF0uZGF0YTtcblxuICAgIH0pXG5cdH1cblxuXHRyZXR1cm4gUHJvZHVjdExpc3RGYWN0b3J5O1xuXG59KVxuIiwiYXBwLmNvbnRyb2xsZXIoJ1Byb2R1Y3RMaXN0Q3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIHByb2R1Y3RzLCBQcm9kdWN0LCBVdGlsaXR5KSB7XG4gICRzY29wZS5wcm9kdWN0cyA9IHByb2R1Y3RzO1xuICAkc2NvcGUuZmlsdGVyT2JqID0ge307XG5cbiAgJHNjb3BlLmFkZFRvRmlsdGVyID0gZnVuY3Rpb24ocHJvcGVydHksIHF1ZXJ5KXtcbiAgXHQkc2NvcGUuZmlsdGVyT2JqW3Byb3BlcnR5XSA9IHF1ZXJ5O1xuICBcdHZhciBzdXBlclF1ZXJ5ID0gVXRpbGl0eS5jb252ZXJ0VG9RdWVyeSgkc2NvcGUuZmlsdGVyT2JqKTtcbiAgXHRQcm9kdWN0LmdldEFsbChzdXBlclF1ZXJ5KVxuICBcdC50aGVuKHByb2R1Y3RzID0+IHtcbiAgXHRcdCRzY29wZS5wcm9kdWN0cyA9IHByb2R1Y3RzO1xuICBcdH0pXG4gIH1cblxuICAkc2NvcGUucmVtb3ZlRnJvbUZpbHRlciA9IGZ1bmN0aW9uKHByb3BlcnR5KXtcbiAgXHRkZWxldGUgJHNjb3BlLmZpbHRlck9ialtwcm9wZXJ0eV07XG4gIFx0dmFyIHN1cGVyUXVlcnkgPSBVdGlsaXR5LmNvbnZlcnRUb1F1ZXJ5KCRzY29wZS5maWx0ZXJPYmopO1xuICBcdFByb2R1Y3QuZ2V0QWxsKHN1cGVyUXVlcnkpXG4gIFx0LnRoZW4ocHJvZHVjdHMgPT4ge1xuICBcdFx0JHNjb3BlLnByb2R1Y3RzID0gcHJvZHVjdHM7XG4gIFx0fSlcbiAgfVxuXG4gICRzY29wZS5jaGFuZ2VGaWx0ZXIgPSBmdW5jdGlvbihwcm9wZXJ0eSwgcXVlcnksIHRoZUNoZWNrKXtcbiAgXHRpZigkc2NvcGVbdGhlQ2hlY2tdKXtcbiAgXHRcdCRzY29wZS5hZGRUb0ZpbHRlcihwcm9wZXJ0eSwgcXVlcnkpO1xuICBcdH0gZWxzZSB7XG4gIFx0XHQkc2NvcGUucmVtb3ZlRnJvbUZpbHRlcihwcm9wZXJ0eSk7XG4gIFx0fVxuICB9XG4gIFxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAkc3RhdGVQcm92aWRlci5zdGF0ZSgncHJvZHVjdHMnLCB7XG4gICAgdXJsOiAnL3Byb2R1Y3RzJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL3Byb2R1Y3QvbGlzdC9wcm9kdWN0Lmxpc3QuaHRtbCcsXG4gICAgY29udHJvbGxlcjogJ1Byb2R1Y3RMaXN0Q3RybCcsXG4gICAgcmVzb2x2ZToge1xuICAgICAgcHJvZHVjdHM6IGZ1bmN0aW9uIChQcm9kdWN0KSB7XG4gICAgICAgIHJldHVybiBQcm9kdWN0LmdldEFsbCgpO1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5jb250cm9sbGVyKCdQcm9maWxlQWRkcmVzc0N0cmwnLCBmdW5jdGlvbigkc2NvcGUsIGFkZHJlc3NlcywgQWRkcmVzcywgJHJvb3RTY29wZSl7XG4gICRyb290U2NvcGUuYWRkcmVzc2VzID0gYWRkcmVzc2VzO1xufSlcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdwcm9maWxlLmFkZHJlc3NlcycsIHtcbiAgICB1cmw6ICcvYWRkcmVzc2VzJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL3Byb2ZpbGUvYWRkcmVzc2VzL215YWRkcmVzc2VzLmh0bWwnLFxuICAgIGNvbnRyb2xsZXI6ICdQcm9maWxlQWRkcmVzc0N0cmwnLFxuICAgIHJlc29sdmU6IHtcbiAgICAgIGFkZHJlc3NlczogZnVuY3Rpb24oQWRkcmVzcykge1xuICAgICAgICByZXR1cm4gQWRkcmVzcy5nZXRNeUFkZHJlc3NlcygpO1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5jb250cm9sbGVyKCdQcm9maWxlT3JkZXJzQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgb3JkZXJTdW1tYXJpZXMsIE9yZGVyKXtcbiAgJHNjb3BlLm9yZGVyU3VtbWFyaWVzID0gb3JkZXJTdW1tYXJpZXM7XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3Byb2ZpbGUub3JkZXJzJywge1xuICAgIHVybDogJy9vcmRlcnMnLFxuICAgIHRlbXBsYXRlVXJsOiAnanMvcHJvZmlsZS9vcmRlcnMvbXlvcmRlcnMuaHRtbCcsXG4gICAgY29udHJvbGxlcjogJ1Byb2ZpbGVPcmRlcnNDdHJsJyxcbiAgICByZXNvbHZlOiB7XG4gICAgICBvcmRlclN1bW1hcmllczogZnVuY3Rpb24oT3JkZXIpIHtcbiAgICAgICAgcmV0dXJuIE9yZGVyLmdldE15T3JkZXJTdW1tYXJpZXMoKTtcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufSk7XG4iLCJhcHAuY29udHJvbGxlcignUHJvZmlsZUNhcmRzQ3RybCcsIGZ1bmN0aW9uKCRzY29wZSwgY2FyZHMsICRyb290U2NvcGUpe1xuICAkcm9vdFNjb3BlLmNhcmRzID0gY2FyZHM7XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3Byb2ZpbGUuY2FyZHMnLCB7XG4gICAgdXJsOiAnL2NhcmRzJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL3Byb2ZpbGUvY2FyZHMvY2FyZHMuaHRtbCcsXG4gICAgY29udHJvbGxlcjogJ1Byb2ZpbGVDYXJkc0N0cmwnLFxuICAgIHJlc29sdmU6IHtcbiAgICAgIGNhcmRzOiBmdW5jdGlvbihDYXJkKSB7XG4gICAgICAgIHJldHVybiBDYXJkLmdldE15Q2FyZHMoKVxuICAgICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2FkbWluTmF2JywgZnVuY3Rpb24oQXV0aFNlcnZpY2UsICRyb290U2NvcGUpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgc2NvcGU6IHt9LFxuICAgIHRlbXBsYXRlVXJsOiAnanMvYWRtaW4vZGlyZWN0aXZlcy9odG1sL25hdi5hZG1pbi5odG1sJyxcbiAgICBsaW5rOiBmdW5jdGlvbihzY29wZSl7XG4gICAgICB2YXIgc2V0VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSB1c2VyO1xuICAgICAgICAgIH0pO1xuICAgICAgfTtcbiAgICAgIHNjb3BlLnNlYXJjaCA9IHtcbiAgICAgICAgYWRtaW5TZWFyY2g6ICcnXG4gICAgICB9XG5cbiAgICAgIHNjb3BlLnNlYXJjaGluZyA9IGZ1bmN0aW9uKCl7XG4gICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdCgnc2VhcmNoaW5nJywgc2NvcGUuc2VhcmNoKVxuICAgICAgfVxuICAgICAgc2V0VXNlcigpXG4gICAgfVxuICB9XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3Byb2R1Y3RMaXN0QWRtaW4nLCBmdW5jdGlvbigpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9hZG1pbi9kaXJlY3RpdmVzL2h0bWwvcHJvZHVjdC5saXN0LmFkbWluLmh0bWwnLFxuICB9XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3VzZXJMaXN0QWRtaW4nLCBmdW5jdGlvbigpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9hZG1pbi9kaXJlY3RpdmVzL2h0bWwvdXNlcnMubGlzdC5hZG1pbi5odG1sJyxcbiAgfVxufSk7XG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5kaXJlY3RpdmUoJ2FkZHJlc3NGb3JtJywgZnVuY3Rpb24oJHJvb3RTY29wZSwgQWRkcmVzcyl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2FkZHJlc3MvYWRkcmVzcy1mb3JtLmh0bWwnLFxuICAgIGxpbms6IGZ1bmN0aW9uKHNjb3BlLCBlbGVtLCBhdHRycyl7XG4gICAgICBzY29wZS5jcmVhdGVBZGRyZXNzID0gZnVuY3Rpb24oaW5mb3JtYXRpb24sIHVzZXIpe1xuICAgICAgICBBZGRyZXNzLmNyZWF0ZU5ld0FkZHJlc3MoaW5mb3JtYXRpb24sIHVzZXIpXG4gICAgICAgIC50aGVuKGFkZHJlc3MgPT4ge1xuICAgICAgICAgICRyb290U2NvcGUuYWRkcmVzc2VzLnB1c2goYWRkcmVzcyk7XG4gICAgICAgICAgc2NvcGUuaW5mb3JtYXRpb24gPSB7fTtcbiAgICAgICAgICBzY29wZS5hZGRBZGRyZXNzLiRzZXRQcmlzdGluZSgpXG4gICAgICAgIH0pXG4gICAgICB9XG4gICAgfVxuICB9XG59KTtcbiIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmRpcmVjdGl2ZSgnYWRkcmVzcycsIGZ1bmN0aW9uKCRyb290U2NvcGUsIEFkZHJlc3Mpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9hZGRyZXNzL2FkZHJlc3MuaHRtbCcsXG4gICAgc2NvcGU6IHtcbiAgICAgIGFkZHJlc3M6ICc9bW9kZWwnXG4gICAgfSxcbiAgICBsaW5rOiBmdW5jdGlvbihzY29wZSwgZWxlbSwgYXR0cnMpe1xuICAgICAgc2NvcGUuZGVsZXRlQWRkcmVzcyA9IGZ1bmN0aW9uKGFkZHJlc3NJZCwgdXNlcklkKXtcbiAgICAgICAgQWRkcmVzcy5yZW1vdmVBZGRyZXNzRnJvbVVzZXIoYWRkcmVzc0lkLCB1c2VySWQpXG4gICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAkcm9vdFNjb3BlLmFkZHJlc3Nlcy5mb3JFYWNoKChhZGRyZXNzLCBpKSA9PiB7XG4gICAgICAgICAgICBpZihhZGRyZXNzLmlkID09PSBhZGRyZXNzSWQpe1xuICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFkZHJlc3Nlcy5zcGxpY2UoaSwgMSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KVxuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goZXJyb3IgPT4gY29uc29sZS5lcnJvcihlcnJvcikpXG4gICAgICB9XG4gICAgfVxuICB9XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2Z1bGxzdGFja0xvZ28nLCBmdW5jdGlvbiAoKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9mdWxsc3RhY2stbG9nby9mdWxsc3RhY2stbG9nby5odG1sJ1xuICAgIH07XG59KTsiLCJhcHAuZGlyZWN0aXZlKCdwYXltZW50JywgZnVuY3Rpb24oJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsIEFVVEhfRVZFTlRTLCAkc3RhdGUpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHNjb3BlOiB7fSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9jaGVja291dC9wYXltZW50Lmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbihzY29wZSkge1xuICAgICAgICAgICAgc2NvcGUuc3VibWl0UGF5bWVudCA9IGZ1bmN0aW9uKGNoZWNrb3V0KSB7XG4gICAgICAgICAgICAgICAgLy93ZSBtdXN0IGFkZCBjcmVhdGVQYXltZW50IHRvIHRoZSBvcmRlciBmYWN0b3J5XG4gICAgICAgICAgICAgICAgb3JkZXIuY3JlYXRlUGF5bWVudCgkc2NvcGUubmV3T3JkZXIpXG4gICAgICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2hvdyBjb25maXJtYXRpb24gbW9kYWxcbiAgICAgICAgICAgICAgICAgICAgICAgICR1aWJNb2RhbC5vcGVuKHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZW1wbGF0ZVVybDogJy9qcy9jaGVja291dC9jb25maXJtYXRpb24uaHRtbCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udHJvbGxlcjogWyckc2NvcGUnLCAnJHVpYk1vZGFsSW5zdGFuY2UnLCAnJHN0YXRlJywgZnVuY3Rpb24oJHNjb3BlLCAkdWliTW9kYWxJbnN0YW5jZSwgJHN0YXRlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5vayA9IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHVpYk1vZGFsSW5zdGFuY2UuY2xvc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1dXG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygncHJvZHVjdHMnKTtcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgLmNhdGNoKGVycm9yID0+IGNvbnNvbGUuZXJyb3IoZXJyb3IpKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxufSlcbiIsImFwcC5kaXJlY3RpdmUoJ25hdmJhcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgQVVUSF9FVkVOVFMsICRzdGF0ZSkge1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgc2NvcGU6IHt9LFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuXG4gICAgICAgICAgICBzY29wZS5pdGVtcyA9IFtcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnSG9tZScsIHN0YXRlOiAnaG9tZScgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnUHJvZHVjdHMnLCBzdGF0ZTogJ3Byb2R1Y3RzJ30sXG4gICAgICAgICAgICBdO1xuICAgICAgICAgICAgc2NvcGUuaXNBZG1pbiA9IGZhbHNlO1xuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHNldFVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gdXNlcjtcbiAgICAgICAgICAgICAgICAgICAgaWYoc2NvcGUudXNlci5pc0FkbWluKSBzY29wZS5pc0FkbWluID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHJlbW92ZVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG4gICAgICAgICAgICAgICAgc2NvcGUuaXNBZG1pbiA9IGZhbHNlO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2V0VXNlcigpO1xuXG5cbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzLCByZW1vdmVVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCByZW1vdmVVc2VyKTtcblxuICAgICAgICB9XG5cbiAgICB9O1xuXG59KTtcbiIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmRpcmVjdGl2ZSgnb3JkZXJEZXRhaWwnLCBmdW5jdGlvbihPcmRlcil7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL29yZGVycy9vcmRlci5kZXRhaWwuaHRtbCcsXG4gICAgc2NvcGU6IHtcbiAgICAgIG9yZGVyRGV0YWlsOiAnPW1vZGVsJ1xuICAgIH1cbiAgfVxufSk7XG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5kaXJlY3RpdmUoJ29yZGVyU3VtbWFyeScsIGZ1bmN0aW9uKE9yZGVyLCBBdXRoU2VydmljZSwgJHJvb3RTY29wZSl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL29yZGVycy9vcmRlci5zdW1tYXJ5Lmh0bWwnLFxuICAgIHNjb3BlOiB7XG4gICAgICBvcmRlclN1bW1hcnk6ICc9bW9kZWwnXG4gICAgfSxcbiAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUsIGVsZW0sIGF0dHJzKSB7XG4gICAgICBzY29wZS5kZXRhaWxzID0ge307XG4gICAgICBzY29wZS5zaG93ID0ge307XG4gICAgICBzY29wZS5vcmRlclN1bW1hcnkucHJpY2VUb3RhbCA9IHNjb3BlLm9yZGVyU3VtbWFyeS5wcmljZVRvdGFsIC8gMTAwO1xuXG4gICAgICBmdW5jdGlvbiBnZXRPcmRlckRldGFpbHMoaWQpe1xuICAgICAgICBpZihzY29wZS5kZXRhaWxzW2lkXSkgc2NvcGUuc2hvd1tpZF0gPSB0cnVlO1xuICAgICAgICBlbHNlIHtcbiAgICAgICAgICBpZigkcm9vdFNjb3BlLmlzQWRtaW4pIHtcbiAgICAgICAgICAgIE9yZGVyLmdldEFsbE9yZGVyRGV0YWlscyhpZClcbiAgICAgICAgICAgIC50aGVuKGRldGFpbHMgPT4ge1xuICAgICAgICAgICAgICBzY29wZS5zaG93W2lkXSA9IHRydWU7XG4gICAgICAgICAgICAgIHNjb3BlLmRldGFpbHNbaWRdID0gZGV0YWlscztcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIE9yZGVyLmdldE15T3JkZXJEZXRhaWxzKGlkKVxuICAgICAgICAgICAgLnRoZW4oZGV0YWlscyA9PiB7XG4gICAgICAgICAgICAgIHNjb3BlLnNob3dbaWRdID0gdHJ1ZTtcbiAgICAgICAgICAgICAgc2NvcGUuZGV0YWlsc1tpZF0gPSBkZXRhaWxzO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICB9XG5cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBzY29wZS50b2dnbGUgPSBmdW5jdGlvbihpZCl7XG4gICAgICAgIGlmKHNjb3BlLnNob3dbaWRdKSBzY29wZS5zaG93W2lkXSA9IGZhbHNlO1xuICAgICAgICBlbHNlIGdldE9yZGVyRGV0YWlscyhpZCk7XG4gICAgICB9XG4gICAgfVxuICB9XG59KTtcbiIsIid1c2Ugc3RyaWN0JztcblxuYXBwLmRpcmVjdGl2ZSgnY2FyZEZvcm0nLCBmdW5jdGlvbihDYXJkLCAkcm9vdFNjb3BlKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9wYXltZW50LWNhcmRzL2NhcmQtZm9ybS5odG1sJyxcbiAgICAgICAgc2NvcGU6IHtcbiAgICAgICAgICAgIHVzZXJJZDogJz0nXG4gICAgICAgIH0sXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uKHNjb3BlLCBlbGVtLCBhdHRycykge1xuICAgICAgICAgICAgc2NvcGUuc3VibWl0Q2FyZCA9IGZ1bmN0aW9uKGNhcmQpIHtcbiAgICAgICAgICAgICAgICBpZiAoc2NvcGUudXNlcklkKSB7XG4gICAgICAgICAgICAgICAgICAgIENhcmQuY3JlYXRlTmV3Q2FyZEZvclVzZXIoY2FyZClcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oY2FyZCA9PiAkcm9vdFNjb3BlLmNhcmRzLnB1c2goY2FyZCkpXG4gICAgICAgICAgICAgICAgfSBlbHNlIENhcmQuY3JlYXRlTmV3Q2FyZE5vVXNlcihjYXJkKVxuICAgICAgICAgICAgICAgICAgICAudGhlbihjYXJkID0+ICRyb290U2NvcGUuY2FyZHMucHVzaChjYXJkKSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn0pO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZGlyZWN0aXZlKCdwYXltZW50Q2FyZCcsIGZ1bmN0aW9uKCl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL3BheW1lbnQtY2FyZHMvcGF5bWVudC1jYXJkLmh0bWwnLFxuICAgIHNjb3BlOiB7XG4gICAgICBjYXJkOiAnPW1vZGVsJ1xuICAgIH1cbiAgfVxufSk7XG4iLCIndXNlIHN0cmljdCc7XG5cbmFwcC5kaXJlY3RpdmUoJ2FkZFRvQ2FydCcsIGZ1bmN0aW9uKFByb2R1Y3RMaXN0RmFjdG9yeSwgJHN0YXRlKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9wcm9kdWN0cy9wcm9kdWN0LmFkZC10by1jYXJ0Lmh0bWwnLFxuICAgICAgICBzY29wZToge1xuICAgICAgICAgICAgcHJvZHVjdDogJz1tb2RlbCdcbiAgICAgICAgfSxcbiAgICAgICAgbGluazogZnVuY3Rpb24oc2NvcGUsIGVsZW0sIGF0dHJzKSB7XG4gICAgICAgICAgICBzY29wZS5hZGRlZCA9IGZhbHNlO1xuICAgICAgICAgICAgc2NvcGUucXVhbnRpdGllcyA9IFsxLCAyLCAzLCA0LCA1LCA2LCA3LCA4LCA5LCAxMF07XG4gICAgICAgICAgICBzY29wZS5xdWFudGl0eSA9IHNjb3BlLnF1YW50aXRpZXNbMF07XG4gICAgICAgICAgICBzY29wZS5hZGRUb0NhcnQgPSBmdW5jdGlvbihwcm9kdWN0KSB7XG4gICAgICAgICAgICAgICAgc2NvcGUuYWRkZWQgPSB0cnVlO1xuICAgICAgICAgICAgICAgIFByb2R1Y3RMaXN0RmFjdG9yeS5hZGRQcm9kdWN0KHByb2R1Y3QsIHNjb3BlLnF1YW50aXR5KVxuICAgICAgICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdjYXJ0Jyk7XG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn0pO1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG5hcHAuZGlyZWN0aXZlKCdwcm9kdWN0TGlzdCcsIGZ1bmN0aW9uKCl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL3Byb2R1Y3RzL3Byb2R1Y3QubGlzdC5odG1sJyxcbiAgICBzY29wZToge1xuICAgICAgcHJvZHVjdDogJz1tb2RlbCdcbiAgICB9LFxuICAgIGxpbms6IGZ1bmN0aW9uKHNjb3BlLCBlbGVtLCBhdHRycykge1xuICAgICAgc2NvcGUucHJvZHVjdC5kZXNjcmlwdGlvbiA9IHNjb3BlLnByb2R1Y3QuZGVzY3JpcHRpb24uc3Vic3RyaW5nKDAsIDEwMCk7XG4gICAgfVxuICB9XG59KTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
