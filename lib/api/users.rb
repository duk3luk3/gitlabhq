module API
  # Users API
  class Users < Grape::API
    before { authenticate! }

    resource :users do
      # Get a users list
      #
      # Example Request:
      #  GET /users
      get do
        @users = User.all
        @users = @users.active if params[:active].present?
        @users = @users.search(params[:search]) if params[:search].present?
        @users = paginate @users

        if current_user.is_admin?
          present @users, with: Entities::UserFull
        else
          present @users, with: Entities::UserBasic
        end
      end

      # Get a single user
      #
      # Parameters:
      #   id (required) - The ID of a user
      # Example Request:
      #   GET /users/:id
      get ":id" do
        @user = User.find(params[:id])

        if current_user.is_admin?
          present @user, with: Entities::UserFull
        else
          present @user, with: Entities::UserBasic
        end
      end

      # Create user. Available only for admin
      #
      # Parameters:
      #   email (required)                                       - Email
      #   password (required unless force_random_password set)   - Password
      #   force_random_password (required unless password set)   - generate random password for user - true or false
      #   name (required)                                        - Name
      #   username (required)                                    - username
      #   skype                                                  - Skype ID
      #   linkedin                                               - Linkedin
      #   twitter                                                - Twitter account
      #   website_url                                            - Website url
      #   projects_limit                                         - Number of projects user can create
      #   extern_uid                                             - External authentication provider UID
      #   provider                                               - External provider
      #   bio                                                    - Bio
      #   admin                                                  - User is admin - true or false (default)
      #   can_create_group                                       - User can create groups - true or false
      # Example Request:
      #   POST /users
      post do
        authenticated_as_admin!

        required_attributes! [:email, :name, :username]
        attrs = attributes_for_keys [:email, :name, :skype, :linkedin,
                                     :twitter, :projects_limit, :username,
                                     :extern_uid, :provider, :bio,
                                     :can_create_group, :admin]

        force_random =  params[:force_random_password] &&
          (params[:force_random_password].to_i > 0)

        if params[:password] && !force_random
          attrs[:password] = params[:password]
        elsif force_random && !params[:password]
          attrs[:force_random_password] = true
        else
          render_api_error!('400 Either password or force_random_password'\
                            ' must be set', 400)
        end

        admin = attrs.delete(:admin)
        user = User.new(attrs)

        user.admin = admin unless admin.nil?
        if force_random
          user.created_by_id = current_user.id
          user.password_expires_at = nil
          user.generate_reset_token
          user.skip_confirmation!
        end

        if not user.valid?
          render_api_error!(['400 Bad', user.errors.first[0].to_s + ':',
                             user.errors.first[1]].join(' '), 400)
        end
        if user.save
          present user, with: Entities::UserFull
        else
          not_found!
        end
      end

      # Update user. Available only for admin
      #
      # Parameters:
      #   email                             - Email
      #   name                              - Name
      #   password                          - Password
      #   skype                             - Skype ID
      #   linkedin                          - Linkedin
      #   twitter                           - Twitter account
      #   website_url                       - Website url
      #   projects_limit                    - Limit projects each user can create
      #   extern_uid                        - External authentication provider UID
      #   provider                          - External provider
      #   bio                               - Bio
      #   admin                             - User is admin - true or false (default)
      #   can_create_group                  - User can create groups - true or false
      # Example Request:
      #   PUT /users/:id
      put ":id" do
        authenticated_as_admin!

        attrs = attributes_for_keys [:email, :name, :password, :skype, :linkedin, :twitter, :website_url, :projects_limit, :username, :extern_uid, :provider, :bio, :can_create_group, :admin]
        user = User.find(params[:id])
        not_found!("User not found") unless user

        admin = attrs.delete(:admin)
        user.admin = admin unless admin.nil?
        if user.update_attributes(attrs)
          present user, with: Entities::UserFull
        else
          not_found!
        end
      end

      # Add ssh key to a specified user. Only available to admin users.
      #
      # Parameters:
      # id (required) - The ID of a user
      # key (required) - New SSH Key
      # title (required) - New SSH Key's title
      # Example Request:
      # POST /users/:id/keys
      post ":id/keys" do
        authenticated_as_admin!
        user = User.find(params[:id])
        attrs = attributes_for_keys [:title, :key]
        key = user.keys.new attrs
        if key.save
          present key, with: Entities::SSHKey
        else
          not_found!
        end
      end

      # Get ssh keys of a specified user. Only available to admin users.
      #
      # Parameters:
      # uid (required) - The ID of a user
      # Example Request:
      # GET /users/:uid/keys
      get ':uid/keys' do
        authenticated_as_admin!
        user = User.find_by(id: params[:uid])
        if user
          present user.keys, with: Entities::SSHKey
        else
          not_found!
        end
      end

      # Delete existing ssh key of a specified user. Only available to admin
      # users.
      #
      # Parameters:
      #   uid (required) - The ID of a user
      #   id (required) - SSH Key ID
      # Example Request:
      #   DELETE /users/:uid/keys/:id
      delete ':uid/keys/:id' do
        authenticated_as_admin!
        user = User.find_by(id: params[:uid])
        if user
          begin
            key = user.keys.find params[:id]
            key.destroy
          rescue ActiveRecord::RecordNotFound
            not_found!
          end
        else
          not_found!
        end
      end

      # Delete user. Available only for admin
      #
      # Example Request:
      #   DELETE /users/:id
      delete ":id" do
        authenticated_as_admin!
        user = User.find_by(id: params[:id])

        if user
          user.destroy
        else
          not_found!
        end
      end
    end

    resource :user do
      # Get currently authenticated user
      #
      # Example Request:
      #   GET /user
      get do
        present @current_user, with: Entities::UserLogin
      end

      # Get currently authenticated user's keys
      #
      # Example Request:
      #   GET /user/keys
      get "keys" do
        present current_user.keys, with: Entities::SSHKey
      end

      # Get single key owned by currently authenticated user
      #
      # Example Request:
      #   GET /user/keys/:id
      get "keys/:id" do
        key = current_user.keys.find params[:id]
        present key, with: Entities::SSHKey
      end

      # Add new ssh key to currently authenticated user
      #
      # Parameters:
      #   key (required) - New SSH Key
      #   title (required) - New SSH Key's title
      # Example Request:
      #   POST /user/keys
      post "keys" do
        required_attributes! [:title, :key]

        attrs = attributes_for_keys [:title, :key]
        key = current_user.keys.new attrs
        if key.save
          present key, with: Entities::SSHKey
        else
          not_found!
        end
      end

      # Delete existing ssh key of currently authenticated user
      #
      # Parameters:
      #   id (required) - SSH Key ID
      # Example Request:
      #   DELETE /user/keys/:id
      delete "keys/:id" do
        begin
          key = current_user.keys.find params[:id]
          key.destroy
        rescue
        end
      end
    end
  end
end
