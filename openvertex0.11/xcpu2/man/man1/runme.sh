for i in *.t2m; do j=`echo $i | sed 's/.t2m//'`; txt2man -t "$j 1" < $i > $j.1; echo $i; done

