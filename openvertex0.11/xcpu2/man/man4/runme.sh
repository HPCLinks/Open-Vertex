for i in *.t2m; do j=`echo $i | sed 's/.t2m//'`; txt2man -t "$j 4" < $i > $j.4; echo $i; done

