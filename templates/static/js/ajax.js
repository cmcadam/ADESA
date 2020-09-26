function ad_auditor() {
    const server_id = document.getElementById('server_id').value;
    $.ajax({
        url: "/ad/auditor/authorize/" + server_id + "/",
        type: 'POST',
        data : {
            username: document.getElementById('id_username').value,
            password: document.getElementById('id_password').value,
            csrfmiddlewaretoken : $('[name=csrfmiddlewaretoken]').val(),
        },
        beforeSend: function(){
            $('#loader').show();
            console.log('loading')
        },
        complete: function(){
            $('#loader').hide();
        },
        success : function() {
            console.log('succcesss');
        },
        error : function() {
            console.log('errors');
        }
    })
}