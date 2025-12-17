break min_poc.c:75
# break main
# set exec-wrapper env -i
# r

define xbt
  set $xbp = (void **)$arg0
  while 1
    x/2a $xbp
    set $xbp = (void **)$xbp[0]
  end
end

