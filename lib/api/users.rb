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
        @users = User.scoped
        @users = @users.active if params[:active].present?
        @users = @users.search(params[:search]) if params[:search].present?
        @users = paginate @users
        present @users, with: Entities::User
      end

      # Get a single user
      #
      # Parameters:
      #   id (required) - The ID of a user
      # Example Request:
      #   GET /users/:id
      get ":id" do
        @user = User.find(params[:id])
        present @user, with: Entities::User
      end

      # Create user. Available only for admin
      #
      # Parameters:
      #   email (required)                  - Email
      #   password (semi-required)          - Password
      #   name (required)                   - Name
      #   username (required)               - username
      #   skype                             - Skype ID
      #   linkedin                          - Linkedin
      #   twitter                           - Twitter account
      #   projects_limit                    - Number of projects user can create
      #   extern_uid                        - External authentication provider UID
      #   provider                          - External provider
      #   bio                               - Bio
      #   expired_password                  - password is set expired
      #   force_random_password             - generate random password for user
      # Example Request:
      #   POST /users
      post do
        authenticated_as_admin!
        required_attributes! [:email, :name, :username]

        attrs = attributes_for_keys [:email, :name, :skype, :linkedin, :twitter, :projects_limit, :username, :extern_uid, :provider, :bio]

        #parse password strategy params
        expired = params[:expired_password] && (params[:expired_password].to_i > 0)
        force_random =  params[:force_random_password] && (params[:force_random_password].to_i > 0)

        #check params set properly
        if !(force_random ^ params[:password].present?)
          render_api_error!('400 Either password or force_random must be set',400)
        end

        attrs[:password_expires_at] = Time.now if expired

        if force_random
          attrs[:force_random_password] = true
        else
          attrs[:password] = params[:password]
        end

        user = User.new attrs, as: :admin
        user.created_by_id = current_user.id if expired # this is necessary to make the new user notification work correctly.

        if user.save
          present user, with: Entities::User
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
      #   projects_limit                    - Limit projects each user can create
      #   extern_uid                        - External authentication provider UID
      #   provider                          - External provider
      #   bio                               - Bio
      # Example Request:
      #   PUT /users/:id
      put ":id" do
        authenticated_as_admin!

        attrs = attributes_for_keys [:email, :name, :password, :skype, :linkedin, :twitter, :projects_limit, :username, :extern_uid, :provider, :bio]
        user = User.find(params[:id])
        not_found!("User not found") unless user

        if user.update_attributes(attrs)
          present user, with: Entities::User
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

      # Delete user. Available only for admin
      #
      # Example Request:
      #   DELETE /users/:id
      delete ":id" do
        authenticated_as_admin!
        user = User.find_by_id(params[:id])

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
