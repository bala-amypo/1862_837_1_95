echo "Testing cat command..."
   2 cat << EOF > test_file.txt
   3 This is a test.
   4 EOF
   5 cat test_file.txt