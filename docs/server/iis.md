# IIS

IIS FastCGI exposes request data through server variables. Header order is not reliable. ARR and load balancers can affect client IP detection, so configure trusted proxies explicitly.