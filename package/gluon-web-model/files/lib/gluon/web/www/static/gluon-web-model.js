!function(){var f={};function a(e){return/^-?\d+$/.test(e)?+e:NaN}function r(e){return/^-?\d*\.?\d+?$/.test(e)?+e:NaN}var u={integer:function(){return!isNaN(a(this))},uinteger:function(){return 0<=a(this)},float:function(){return!isNaN(r(this))},ufloat:function(){return 0<=r(this)},ipaddr:function(){return u.ip4addr.apply(this)||u.ip6addr.apply(this)},ip4addr:function(){var e;return!!(e=this.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/))&&(0<=e[1]&&e[1]<=255&&0<=e[2]&&e[2]<=255&&0<=e[3]&&e[3]<=255&&0<=e[4]&&e[4]<=255)},ip6addr:function(){return this.indexOf("::")<0?null!=this.match(/^(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}$/i):!(0<=this.indexOf(":::")||this.match(/::.+::/)||this.match(/^:[^:]/)||this.match(/[^:]:$/))&&(!!this.match(/^(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i)||(!!this.match(/^(?:[a-f0-9]{1,4}:){7}:$/i)||!!this.match(/^:(?::[a-f0-9]{1,4}){7}$/i)))},wpakey:function(){var e=this;return 64==e.length?null!=e.match(/^[a-f0-9]{64}$/i):8<=e.length&&e.length<=63},range:function(e,t){var n=r(this);return+e<=n&&n<=+t},min:function(e){return r(this)>=+e},max:function(e){return r(this)<=+e},irange:function(e,t){var n=a(this);return+e<=n&&n<=+t},imin:function(e){return a(this)>=+e},imax:function(e){return a(this)<=+e},minlength:function(e){return+e<=(""+this).length},maxlength:function(e){return(""+this).length<=+e}};function o(e){for(var t=0;t<e.length;t++){var n=!0;for(var a in e[t])n=n&&(r=a,i=e[t][a],o=void 0,(o=document.getElementById(r))?("checkbox"==o.type?o.checked:o.value?o.value:"")==i:!!(o=document.getElementById(r+"."+i))&&"radio"==o.type&&o.checked);if(n)return!0}var r,i,o;return!1}function v(){window.dispatchEvent(new Event("gluon-update"));var e=!1;for(var t in f){var n=f[t],a=document.getElementById(t),r=document.getElementById(n.parent);if(a&&a.parentNode&&!o(n.deps))a.parentNode.removeChild(a),a.dispatchEvent(new Event("gluon-hide")),e=!0;else if(r&&(!a||!a.parentNode)&&o(n.deps)){var i=void 0;for(i=r.firstChild;i&&!(i.getAttribute&&parseInt(i.getAttribute("data-index"),10)>n.index);i=i.nextSibling);i?r.insertBefore(n.node,i):r.appendChild(n.node),n.node.dispatchEvent(new Event("gluon-show")),e=!0}r&&r.parentNode&&r.getAttribute("data-optionals")&&(r.parentNode.style.display=r.options.length<=1?"none":"")}e&&v()}function h(e,t,n,a){return e.addEventListener?e.addEventListener(t,n,!!a):e.attachEvent("on"+t,function(){var e=window.event;return!e.target&&e.srcElement&&(e.target=e.srcElement),!!n(e)}),e}function g(l,s){var c=s.prefix;function o(e,t,n){for(var a=[];l.firstChild;){var r=l.firstChild;(i=+r.index)!=n&&("input"==r.nodeName.toLowerCase()?a.push(r.value||""):"select"==r.nodeName.toLowerCase()&&(a[a.length-1]=r.options[r.selectedIndex].value)),l.removeChild(r)}0<=t?(e=t+1,a.splice(t,0,"")):s.optional||0!=a.length||a.push("");for(var i=1;i<=a.length;i++){var o=document.createElement("input");if(o.id=c+"."+i,o.name=c,o.value=a[i-1],o.type="text",o.index=i,o.className="gluon-input-text",s.size&&(o.size=s.size),s.placeholder&&(o.placeholder=s.placeholder),l.appendChild(o),s.type&&m(o,!1,s.type),h(o,"keydown",f),h(o,"keypress",p),i==e)o.focus();else if(-i==e){o.focus();var d=o.value;o.value=" ",o.value=d}if(s.optional||1<a.length)(u=document.createElement("span")).className="gluon-remove",l.appendChild(u),h(u,"click",v(!1)),l.appendChild(document.createElement("br"))}var u;(u=document.createElement("span")).className="gluon-add",l.appendChild(u),h(u,"click",v(!0))}function p(e){var t=(e=e||window.event).target?e.target:e.srcElement;switch(3==t.nodeType&&(t=t.parentNode),e.keyCode){case 8:case 46:return 0!=t.value.length||(e.preventDefault&&e.preventDefault(),!1);case 13:case 38:case 40:return e.preventDefault&&e.preventDefault(),!1}return!0}function f(e){var t,n,a=(e=e||window.event).target?e.target:e.srcElement,r=0;if(a){for(3==a.nodeType&&(a=a.parentNode),r=a.index,t=a.previousSibling;t&&t.name!=c;)t=t.previousSibling;for(n=a.nextSibling;n&&n.name!=c;)n=n.nextSibling}switch(e.keyCode){case 8:case 46:if("select"==a.nodeName.toLowerCase()||0==a.value.length){e.preventDefault&&e.preventDefault();var i=a.index;return 8==e.keyCode&&(i=1-i),o(i,-1,r),!1}break;case 13:o(-1,r,-1);break;case 38:t&&t.focus();break;case 40:n&&n.focus()}return!0}function v(n){return function(e){for(var t=((e=e||window.event).target?e.target:e.srcElement).previousSibling;t&&t.name!=c;)t=t.previousSibling;return n?f({target:t,keyCode:13}):(t.value="",f({target:t,keyCode:8})),!1}}o(NaN,-1,-1)}function m(t,n,e){var a,r,i,o=(i=(a=e).match(/^([^\(]+)\(([^,]+),([^\)]+)\)$/))&&void 0!==(r=u[i[1]])?function(){return r.apply(this,[i[2],i[3]])}:(i=a.match(/^([^\(]+)\(([^,\)]+)\)$/))&&void 0!==(r=u[i[1]])?function(){return r.apply(this,[i[2]])}:u[a];if(o){var d=function(){if(t.form){t.className=t.className.replace(/ gluon-input-invalid/g,"");var e=t.options&&-1<t.options.selectedIndex?t.options[t.options.selectedIndex].value:t.value;0==e.length&&n||o.apply(e)||(t.className+=" gluon-input-invalid")}};h(t,"blur",d),h(t,"keyup",d),h(t,"gluon-revalidate",d),"select"==t.nodeName.toLowerCase()&&(h(t,"change",d),h(t,"click",d)),d()}}!function(){var e,t,n,a,r;e=document.querySelectorAll("[data-depends]");for(var i=0;void 0!==(p=e[i]);i++){var o=parseInt(p.getAttribute("data-index"),10),d=JSON.parse(p.getAttribute("data-depends"));if(!isNaN(o)&&0<d.length)for(var u=0;u<d.length;u++)t=p,n=d[u],a=o,r=void 0,(r=f[t.id])||(r={node:t,parent:t.parentNode.id,deps:[],index:a},f[t.id]=r),r.deps.push(n)}e=document.querySelectorAll("[data-update]");for(i=0;void 0!==(p=e[i]);i++)for(var l,s=p.getAttribute("data-update").split(" "),c=0;void 0!==(l=s[c]);c++)h(p,l,function(){setTimeout(v,0)});e=document.querySelectorAll("[data-type]");for(i=0;void 0!==(p=e[i]);i++)m(p,"true"===p.getAttribute("data-optional"),p.getAttribute("data-type"));e=document.querySelectorAll("[data-dynlist]");var p;for(i=0;void 0!==(p=e[i]);i++){g(p,JSON.parse(p.getAttribute("data-dynlist")))}v()}()}();
