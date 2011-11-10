for i in *.t2m; do j=`echo $i | sed 's/.t2m//'`; txt2man -t "$j 3" < $i > $j.3; echo $i; done

